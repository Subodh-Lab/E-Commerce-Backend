package main

import (
	"log"
	"net/http"
	"strings"

	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var jwtKey = []byte("subodhsinghsecretkey")

var db *gorm.DB

type Admin struct {
	ID       uint   `gorm:"primaryKey"`
	Username string `gorm:"unique"`
	Password string
}
type Item struct {
	ID          uint `gorm:"primaryKey"`
	Name        string
	Description string
	Price       float64
	Quantity    int
	IsAvailable bool `gorm:"default:true"`
	ImageURL    string
}
type Customer struct {
	ID       uint `gorm:"primaryKey"`
	Name     string
	Email    string `gorm:"unique"`
	Password string
	Wallet   float64 `gorm:"default:10000"`
}
type Cart struct {
	ID         uint `gorm:"primaryKey"`
	CustomerID uint
	ProductID  uint
	Quantity   int
}
type Order struct {
	ID         uint `gorm:"primaryKey"`
	CustomerID uint
	ProductID  uint
	Quantity   int
	Total      float64
	Status     string `gorm:"default:'PLACED'"`
}

func connectDB() {
	dsn := "host=localhost user=apple dbname=ecommerce port=5432 sslmode=disable"

	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}

	err = db.AutoMigrate(&Admin{}, &Item{}, &Customer{}, &Cart{}, &Order{})
	if err != nil {
		log.Fatal(err)
	}

	seedAdmin()

	log.Println("DB connected")
}
func GenerateToken(id uint, role string) (string, error) {

	claims := jwt.MapClaims{
		"id":   id,
		"role": role,
		"exp":  time.Now().Add(24 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString(jwtKey)
}
func seedAdmin() {
	var admin Admin

	err := db.Where("username = ?", "admin").First(&admin).Error

	if err == gorm.ErrRecordNotFound {
		hash, _ := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)

		admin = Admin{
			Username: "admin",
			Password: string(hash),
		}

		if err := db.Create(&admin).Error; err != nil {
			log.Println("Failed to create admin:", err)
			return
		}

		log.Println("Default admin created")
	} else if err != nil {
		log.Println("Error checking admin:", err)
	} else {
		log.Println("Admin already exists")
	}
}
func CustomerRegister(c *gin.Context) {
	var req Customer

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	var customer Customer
	if err := db.Where("email = ?", req.Email).First(&customer).Error; err == nil {
		c.JSON(400, gin.H{"error": "email already exists"})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to hash password"})
		return
	}

	req.Password = string(hash)
	req.Wallet = 10000

	db.Create(&req)

	c.JSON(201, gin.H{
		"message": "registered successfully",
	})
}
func Auth(role string) gin.HandlerFunc {

	return func(c *gin.Context) {

		tokenString := c.GetHeader("Authorization")

		if tokenString == "" {
			c.JSON(401, gin.H{"error": "token required"})
			c.Abort()
			return
		}

		tokenString = strings.TrimPrefix(tokenString, "Bearer ")

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {

			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrTokenSignatureInvalid
			}

			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			c.JSON(401, gin.H{"error": "invalid token"})
			c.Abort()
			return
		}
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(401, gin.H{"error": "invalid token"})
			c.Abort()
			return
		}
		if claims["role"] != role {
			c.JSON(403, gin.H{"error": "access denied"})
			c.Abort()
			return
		}

		id := uint(claims["id"].(float64))

		c.Set("customer_id", id)

		c.Next()
	}
}
func CustomerLogin(c *gin.Context) {

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	var customer Customer

	if err := db.Where("email=?", req.Email).First(&customer).Error; err != nil {
		c.JSON(401, gin.H{"error": "invalid credentials"})
		return
	}

	err := bcrypt.CompareHashAndPassword(
		[]byte(customer.Password),
		[]byte(req.Password),
	)

	if err != nil {
		c.JSON(401, gin.H{"error": "invalid credentials"})
		return
	}

	token, _ := GenerateToken(customer.ID, "customer")

	c.JSON(200, gin.H{
		"token": token,
	})
}
func AdminLogin(c *gin.Context) {

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	var admin Admin

	if err := db.Where("username=?", req.Username).First(&admin).Error; err != nil {
		c.JSON(401, gin.H{"error": "invalid credentials"})
		return
	}
	if err := bcrypt.CompareHashAndPassword(
		[]byte(admin.Password),
		[]byte(req.Password),
	); err != nil {
		c.JSON(401, gin.H{"error": "invalid credentials"})
		return
	}

	token, _ := GenerateToken(admin.ID, "admin")

	c.JSON(200, gin.H{
		"token": token,
	})
}
func AddToCart(c *gin.Context) {
	var req struct {
		ProductID uint `json:"product_id"`
		Quantity  int  `json:"quantity"`
	}
	customerID := c.MustGet("customer_id").(uint)

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if req.Quantity <= 0 {
		c.JSON(400, gin.H{"error": "invalid quantity"})
		return
	}
	var item Item

	if err := db.First(&item, req.ProductID).Error; err != nil {
		c.JSON(404, gin.H{"error": "product not found"})
		return
	}

	if !item.IsAvailable {
		c.JSON(400, gin.H{"error": "product unavailable"})
		return
	}

	if req.Quantity > item.Quantity {
		c.JSON(400, gin.H{"error": "stock not available"})
		return
	}

	var cart Cart

	err := db.Where("customer_id = ? AND product_id = ?", customerID, req.ProductID).
		First(&cart).Error

	if err == nil {
		cart.Quantity += req.Quantity
		db.Save(&cart)
		c.JSON(200, gin.H{"message": "cart updated"})
		return
	}

	db.Create(&Cart{
		CustomerID: customerID,
		ProductID:  req.ProductID,
		Quantity:   req.Quantity,
	})

	c.JSON(200, gin.H{"message": "added to cart"})
}

func ViewCart(c *gin.Context) {
	cid := c.MustGet("customer_id").(uint)

	var cart []Cart
	db.Where("customer_id = ?", cid).Find(&cart)

	c.JSON(200, cart)
}
func UpdateCart(c *gin.Context) {
	id := c.Param("id")
	customerID := c.MustGet("customer_id").(uint)

	var cart Cart

	if err := db.Where(
		"id = ? AND customer_id = ?",
		id,
		customerID,
	).First(&cart).Error; err != nil {
		c.JSON(404, gin.H{"error": "not found"})
		return
	}

	var req struct {
		Quantity int `json:"quantity"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	cart.Quantity = req.Quantity
	db.Save(&cart)

	c.JSON(200, gin.H{"message": "updated", "cart": cart})
}
func DeleteCartItem(c *gin.Context) {
	id := c.Param("id")
	customerID := c.MustGet("customer_id").(uint)

	db.Where("id = ? AND customer_id = ?", id, customerID).
		Delete(&Cart{})

	c.JSON(200, gin.H{"message": "deleted"})
}

// func PlaceOrder(c *gin.Context) {
// 	cid := c.GetInt("customer_id")

// 	var customer Customer
// 	db.First(&customer, cid)

// 	var cart []Cart
// 	db.Where("customer_id = ?", cid).Find(&cart)

// 	if len(cart) == 0 {
// 		c.JSON(400, gin.H{"error": "cart empty"})
// 		return
// 	}

// 	for _, v := range cart {

// 		var item Item
// 		db.First(&item, v.ProductID)

// 		if item.Quantity < v.Quantity {
// 			c.JSON(400, gin.H{"error": "stock not available"})
// 			return
// 		}

// 		total := item.Price * float64(v.Quantity)

// 		if customer.Wallet < total {
// 			c.JSON(400, gin.H{"error": "low wallet balance"})
// 			return
// 		}

// 		customer.Wallet -= total
// 		item.Quantity -= v.Quantity

// 		db.Save(&customer)
// 		db.Save(&item)

// 		db.Create(&Order{
// 			CustomerID: uint(cid),
// 			ProductID:  v.ProductID,
// 			Quantity:   v.Quantity,
// 			Total:      total,
// 			Status:     "PLACED",
// 		})
// 	}

// 	db.Where("customer_id = ?", cid).Delete(&Cart{})

// 	c.JSON(200, gin.H{"message": "order placed"})
// }

// func OrderHistory(c *gin.Context) {

// 	cid := c.GetInt("customer_id")

// 	var orders []Order

// 	db.Where("customer_id = ?", cid).Find(&orders)

// 	c.JSON(200, orders)
// }

func AddItem(c *gin.Context) {
	var item Item

	if err := c.ShouldBindJSON(&item); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	if err := db.Create(&item).Error; err != nil {
		c.JSON(500, gin.H{"error": "failed to create item"})
		return
	}
	c.JSON(http.StatusCreated, item)
}

func GetItems(c *gin.Context) {
	var items []Item

	db.Find(&items)

	c.JSON(http.StatusOK, items)
}

func GetItem(c *gin.Context) {
	id := c.Param("id")

	var item Item

	if err := db.First(&item, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "item not found",
		})
		return
	}

	c.JSON(http.StatusOK, item)
}

func UpdateItem(c *gin.Context) {
	id := c.Param("id")

	var item Item

	if err := db.First(&item, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "item not found",
		})
		return
	}

	var input Item

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	if err := db.Model(&item).Updates(input).Error; err != nil {
		c.JSON(500, gin.H{"error": "update failed"})
		return
	}

	c.JSON(http.StatusOK, item)
}

func DeleteItem(c *gin.Context) {
	id := c.Param("id")

	if err := db.Delete(&Item{}, id).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "item deleted",
	})
}

func DisableItem(c *gin.Context) {
	id := c.Param("id")

	var item Item

	if err := db.First(&item, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "item not found",
		})
		return
	}

	item.IsAvailable = false
	db.Save(&item)

	c.JSON(http.StatusOK, gin.H{
		"message": "item disabled",
	})
}

func main() {
	connectDB()
	r := gin.Default()
	r.POST("/api/customer/register", CustomerRegister)
	r.POST("/api/customer/login", CustomerLogin)

	r.POST("/api/admin/login", AdminLogin)

	customer := r.Group("/api/customer")
	customer.Use(Auth("customer"))

	customer.POST("/cart/add", AddToCart)
	customer.GET("/cart", ViewCart)
	customer.PUT("/cart/:id", UpdateCart)
	customer.DELETE("/cart/:id", DeleteCartItem)

	admin := r.Group("/api/admin")
	admin.Use(Auth("admin"))

	admin.POST("/product/add", AddItem)
	admin.GET("/products", GetItems)
	admin.GET("/product/:id", GetItem)
	admin.PUT("/product/:id", UpdateItem)
	admin.DELETE("/product/:id", DeleteItem)
	admin.PATCH("/product/:id/disable", DisableItem)

	r.Run(":8000")
}
