package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/datatypes"
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
	ID        uint `gorm:"primaryKey"`
	Name      string
	Email     string `gorm:"unique"`
	Password  string
	Wallet    float64 `gorm:"default:10000"`
	IsBlocked bool    `gorm:"default:false"`
}
type Cart struct {
	ID         uint           `gorm:"primaryKey"`
	CustomerID uint           `gorm:"uniqueIndex"`
	Items      datatypes.JSON `gorm:"type:jsonb"`
}
type Order struct {
	ID         uint `gorm:"primaryKey"`
	CustomerID uint
	ProductID  uint
	Quantity   int
	Total      float64
	Status     string `gorm:"default:'PENDING_APPROVAL'"`
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
func ForgotPassword(c *gin.Context) {
	var req struct {
		Email string `json:"email"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	var customer Customer

	if err := db.Where("email = ?", req.Email).First(&customer).Error; err != nil {
		c.JSON(404, gin.H{"error": "email not found"})
		return
	}

	claims := jwt.MapClaims{
		"id":  customer.ID,
		"exp": time.Now().Add(15 * time.Minute).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	resetToken, err := token.SignedString(jwtKey)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to generate token"})
		return
	}

	c.JSON(200, gin.H{
		"message": "use this token to reset password",
		"token":   resetToken,
	})
}

func ResetPassword(c *gin.Context) {
	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	token, err := jwt.Parse(req.Token, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		c.JSON(401, gin.H{"error": "invalid or expired token"})
		return
	}

	claims := token.Claims.(jwt.MapClaims)
	id := uint(claims["id"].(float64))

	var customer Customer

	if err := db.First(&customer, id).Error; err != nil {
		c.JSON(404, gin.H{"error": "customer not found"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to hash password"})
		return
	}

	customer.Password = string(hash)

	if err := db.Save(&customer).Error; err != nil {
		c.JSON(500, gin.H{"error": "failed to update password"})
		return
	}

	c.JSON(200, gin.H{
		"message": "password reset successful",
	})
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

	if err := db.Create(&req).Error; err != nil {
		c.JSON(500, gin.H{"error": "failed to create user"})
		return
	}

	token, err := GenerateToken(req.ID, "customer")
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to generate token"})
		return
	}

	c.JSON(201, gin.H{
		"message": "registered successfully",
		"token":   token,
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

		if role == "customer" {
			var customer Customer
			if err := db.First(&customer, id).Error; err != nil {
				c.JSON(401, gin.H{"error": "user not found"})
				c.Abort()
				return
			}

			if customer.IsBlocked {
				c.JSON(403, gin.H{"error": "user is blocked"})
				c.Abort()
				return
			}
		}

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
		c.JSON(400, gin.H{"error": "product not available"})
		return
	}

	if item.Quantity < req.Quantity {
		c.JSON(400, gin.H{"error": "insufficient stock"})
		return
	}

	var cart Cart
	items := map[string]int{}

	err := db.Where("customer_id = ?", customerID).First(&cart).Error
	if err == nil {
		_ = json.Unmarshal(cart.Items, &items)
	} else {
		cart.CustomerID = customerID
	}

	key := strconv.Itoa(int(req.ProductID))
	items[key] += req.Quantity

	newData, _ := json.Marshal(items)
	cart.Items = newData

	if err == nil {
		db.Save(&cart)
	} else {
		db.Create(&cart)
	}

	c.JSON(200, gin.H{
		"message": "cart updated",
		"items":   items,
	})
}
func GetProfile(c *gin.Context) {
	id := c.MustGet("customer_id").(uint)

	var customer Customer

	if err := db.First(&customer, id).Error; err != nil {
		c.JSON(404, gin.H{"error": "user not found"})
		return
	}

	customer.Password = ""

	c.JSON(200, customer)
}
func UpdateProfile(c *gin.Context) {
	id := c.MustGet("customer_id").(uint)

	var customer Customer

	if err := db.First(&customer, id).Error; err != nil {
		c.JSON(404, gin.H{"error": "user not found"})
		return
	}

	var req struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if req.Name != "" {
		customer.Name = req.Name
	}
	if req.Email != "" {
		customer.Email = req.Email
	}

	if err := db.Save(&customer).Error; err != nil {
		c.JSON(500, gin.H{"error": "update failed"})
		return
	}

	customer.Password = ""

	c.JSON(200, customer)
}
func GetInventory(c *gin.Context) {
	var items []Item

	if err := db.Where("is_available = ?", true).Find(&items).Error; err != nil {
		c.JSON(500, gin.H{"error": "failed to fetch inventory"})
		return
	}

	c.JSON(200, items)
}
func GetInventoryByID(c *gin.Context) {
	id := c.Param("id")

	var item Item

	if err := db.Where("id = ? AND is_available = ?", id, true).
		First(&item).Error; err != nil {
		c.JSON(404, gin.H{"error": "item not found"})
		return
	}

	c.JSON(200, item)
}
func ViewCart(c *gin.Context) {
	cid := c.MustGet("customer_id").(uint)

	var cart Cart

	if err := db.Where("customer_id = ?", cid).First(&cart).Error; err != nil {
		c.JSON(404, gin.H{"error": "cart not found"})
		return
	}

	var items map[string]int
	_ = json.Unmarshal(cart.Items, &items)

	c.JSON(200, gin.H{

		"items": items,
	})
}
func UpdateCart(c *gin.Context) {
	customerID := c.MustGet("customer_id").(uint)

	var req struct {
		ProductID uint `json:"product_id"`
		Quantity  int  `json:"quantity"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if req.ProductID == 0 {
		c.JSON(400, gin.H{"error": "invalid product_id"})
		return
	}

	var item Item
	if err := db.First(&item, req.ProductID).Error; err != nil {
		c.JSON(404, gin.H{"error": "product not found"})
		return
	}

	if !item.IsAvailable {
		c.JSON(400, gin.H{"error": "product not available"})
		return
	}

	if req.Quantity > 0 && item.Quantity < req.Quantity {
		c.JSON(400, gin.H{"error": "insufficient stock"})
		return
	}

	var cart Cart
	items := map[string]int{}

	err := db.Where("customer_id = ?", customerID).First(&cart).Error
	if err == nil {
		_ = json.Unmarshal(cart.Items, &items)
	} else {
		cart.CustomerID = customerID
	}

	key := strconv.Itoa(int(req.ProductID))

	if req.Quantity <= 0 {
		delete(items, key)
	} else {
		items[key] = req.Quantity
	}

	newData, _ := json.Marshal(items)
	cart.Items = newData

	if err == nil {
		db.Save(&cart)
	} else {
		db.Create(&cart)
	}

	c.JSON(200, gin.H{
		"message": "cart updated successfully",
		"items":   items,
	})
}
func DeleteCartItem(c *gin.Context) {
	customerID := c.MustGet("customer_id").(uint)

	var req struct {
		ProductID uint `json:"product_id"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if req.ProductID == 0 {
		c.JSON(400, gin.H{"error": "invalid product_id"})
		return
	}

	var cart Cart
	err := db.Where("customer_id = ?", customerID).First(&cart).Error
	if err != nil {
		c.JSON(404, gin.H{"error": "cart not found"})
		return
	}

	items := map[string]int{}
	_ = json.Unmarshal(cart.Items, &items)

	key := strconv.Itoa(int(req.ProductID))

	delete(items, key)

	newData, _ := json.Marshal(items)
	cart.Items = newData

	db.Save(&cart)

	c.JSON(200, gin.H{
		"message": "item removed from cart",
		"items":   items,
	})
}
func ChangeUserStatus(c *gin.Context) {
	id := c.Param("id")

	var user Customer

	if err := db.First(&user, id).Error; err != nil {
		c.JSON(404, gin.H{"error": "user not found"})
		return
	}

	var req struct {
		Status bool `json:"status"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	user.IsBlocked = req.Status

	if err := db.Save(&user).Error; err != nil {
		c.JSON(500, gin.H{"error": "failed to update user status"})
		return
	}

	c.JSON(200, gin.H{
		"message": "user status updated",
		// "user":    user,
	})
}
func GetAllUsers(c *gin.Context) {
	var users []Customer

	if err := db.Find(&users).Error; err != nil {
		c.JSON(500, gin.H{"error": "failed to fetch users"})
		return
	}

	for i := range users {
		users[i].Password = ""
	}

	c.JSON(200, users)
}
func PlaceOrder(c *gin.Context) {
	cid := c.MustGet("customer_id").(uint)

	var cart Cart
	if err := db.Where("customer_id = ?", cid).First(&cart).Error; err != nil {
		c.JSON(400, gin.H{"error": "cart not found"})
		return
	}

	itemsMap := map[string]int{}
	json.Unmarshal(cart.Items, &itemsMap)

	if len(itemsMap) == 0 {
		c.JSON(400, gin.H{"error": "cart empty"})
		return
	}

	var customer Customer
	if err := db.First(&customer, cid).Error; err != nil {
		c.JSON(404, gin.H{"error": "customer not found"})
		return
	}

	tx := db.Begin()

	for productIDStr, qty := range itemsMap {

		productID, _ := strconv.Atoi(productIDStr)

		var item Item
		if err := tx.First(&item, productID).Error; err != nil {
			tx.Rollback()
			c.JSON(404, gin.H{"error": "product not found"})
			return
		}

		if !item.IsAvailable || item.Quantity < qty {
			tx.Rollback()
			c.JSON(400, gin.H{"error": "product unavailable or low stock"})
			return
		}

		err := tx.Create(&Order{
			CustomerID: cid,
			ProductID:  uint(productID),
			Quantity:   qty,
			Total:      item.Price * float64(qty),
			Status:     "PENDING_APPROVAL",
		}).Error

		if err != nil {
			tx.Rollback()
			c.JSON(500, gin.H{"error": "order failed"})
			return
		}
	}

	cart.Items = datatypes.JSON([]byte("{}"))
	db.Save(&cart)

	tx.Commit()

	c.JSON(200, gin.H{
		"message": "order placed successfully",
	})
}
func CancelRequest(c *gin.Context) {
	id := c.Param("id")
	customerID := c.MustGet("customer_id").(uint)

	var order Order

	if err := db.Where("id = ? AND customer_id = ?", id, customerID).First(&order).Error; err != nil {
		c.JSON(404, gin.H{"error": "order not found"})
		return
	}

	if order.Status != "PLACED" {
		c.JSON(400, gin.H{"error": "cancel request not allowed"})
		return
	}

	order.Status = "CANCEL_REQUESTED"

	if err := db.Save(&order).Error; err != nil {
		c.JSON(500, gin.H{"error": "failed to send request"})
		return
	}

	c.JSON(200, gin.H{
		"message": "cancel request sent to admin",
	})
}
func GetCancelRequests(c *gin.Context) {
	var orders []Order

	if err := db.Where("status = ?", "CANCEL_REQUESTED").
		Order("id desc").
		Find(&orders).Error; err != nil {
		c.JSON(500, gin.H{"error": "failed to fetch requests"})
		return
	}

	c.JSON(200, orders)
}
func UpdateCancelRequest(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		Action string `json:"status"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	var order Order

	if err := db.First(&order, id).Error; err != nil {
		c.JSON(404, gin.H{"error": "order not found"})
		return
	}

	if order.Status != "CANCEL_REQUESTED" {
		c.JSON(400, gin.H{"error": "invalid request"})
		return
	}

	switch strings.ToUpper(req.Action) {

	case "ACCEPT":
		tx := db.Begin()

		var item Item
		if err := tx.First(&item, order.ProductID).Error; err != nil {
			tx.Rollback()
			c.JSON(404, gin.H{"error": "product not found"})
			return
		}

		item.Quantity += order.Quantity

		if err := tx.Save(&item).Error; err != nil {
			tx.Rollback()
			c.JSON(500, gin.H{"error": "failed to update stock"})
			return
		}

		var customer Customer
		if err := tx.First(&customer, order.CustomerID).Error; err != nil {
			tx.Rollback()
			c.JSON(404, gin.H{"error": "customer not found"})
			return
		}

		customer.Wallet += order.Total

		if err := tx.Save(&customer).Error; err != nil {
			tx.Rollback()
			c.JSON(500, gin.H{"error": "failed to refund wallet"})
			return
		}

		order.Status = "CANCELLED"

		if err := tx.Save(&order).Error; err != nil {
			tx.Rollback()
			c.JSON(500, gin.H{"error": "failed to update order"})
			return
		}

		tx.Commit()

		c.JSON(200, gin.H{
			"message": "cancel request accepted",
		})

	case "REJECT":
		order.Status = "PLACED"

		if err := db.Save(&order).Error; err != nil {
			c.JSON(500, gin.H{"error": "failed to update order"})
			return
		}

		c.JSON(200, gin.H{
			"message": "cancel request rejected",
		})

	default:
		c.JSON(400, gin.H{"error": "action must be ACCEPT or REJECT"})
	}
}

func OrderHistory(c *gin.Context) {

	cid := c.MustGet("customer_id").(uint)

	var orders []Order

	if err := db.Where("customer_id = ?", cid).
		Order("id desc").
		Find(&orders).Error; err != nil {
		c.JSON(500, gin.H{"error": "failed to fetch orders"})
		return
	}

	c.JSON(200, orders)
}

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
func GetAllOrders(c *gin.Context) {
	var orders []Order

	if err := db.Order("id desc").Find(&orders).Error; err != nil {
		c.JSON(500, gin.H{"error": "failed to fetch orders"})
		return
	}

	c.JSON(200, orders)
}
func GetUserOrders(c *gin.Context) {
	userID := c.Param("id")

	var orders []Order

	if err := db.Where("customer_id = ?", userID).
		Order("id desc").
		Find(&orders).Error; err != nil {
		c.JSON(500, gin.H{"error": "failed to fetch user orders"})
		return
	}

	c.JSON(200, orders)
}
func GetPendingOrders(c *gin.Context) {
	var orders []Order

	db.Where("status = ?", "PENDING_APPROVAL").
		Order("id desc").
		Find(&orders)

	c.JSON(200, orders)
}
func DecideOrder(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		Action string `json:"Status"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	var order Order

	if err := db.First(&order, id).Error; err != nil {
		c.JSON(404, gin.H{"error": "order not found"})
		return
	}

	if order.Status != "PENDING_APPROVAL" {
		c.JSON(400, gin.H{"error": "invalid order status"})
		return
	}

	switch strings.ToUpper(req.Action) {

	case "ACCEPT":
		tx := db.Begin()

		var item Item
		if err := tx.First(&item, order.ProductID).Error; err != nil {
			tx.Rollback()
			c.JSON(404, gin.H{"error": "product not found"})
			return
		}

		if item.Quantity < order.Quantity {
			tx.Rollback()
			c.JSON(400, gin.H{"error": "insufficient stock"})
			return
		}

		var customer Customer
		if err := tx.First(&customer, order.CustomerID).Error; err != nil {
			tx.Rollback()
			c.JSON(404, gin.H{"error": "customer not found"})
			return
		}

		if customer.Wallet < order.Total {
			tx.Rollback()
			c.JSON(400, gin.H{"error": "insufficient wallet"})
			return
		}

		item.Quantity -= order.Quantity
		customer.Wallet -= order.Total

		if err := tx.Save(&item).Error; err != nil {
			tx.Rollback()
			c.JSON(500, gin.H{"error": "stock update failed"})
			return
		}

		if err := tx.Save(&customer).Error; err != nil {
			tx.Rollback()
			c.JSON(500, gin.H{"error": "wallet update failed"})
			return
		}

		order.Status = "PLACED"

		if err := tx.Save(&order).Error; err != nil {
			tx.Rollback()
			c.JSON(500, gin.H{"error": "order update failed"})
			return
		}

		tx.Commit()

		c.JSON(200, gin.H{"message": "order accepted"})

	case "REJECT":
		order.Status = "REJECTED"

		if err := db.Save(&order).Error; err != nil {
			c.JSON(500, gin.H{"error": "failed to reject order"})
			return
		}

		c.JSON(200, gin.H{"message": "order rejected"})

	default:
		c.JSON(400, gin.H{"error": "action must be ACCEPT or REJECT"})
	}
}
func main() {
	connectDB()
	r := gin.Default()
	r.POST("/api/customer/register", CustomerRegister)
	r.POST("/api/customer/login", CustomerLogin)
	r.POST("/api/customer/forgotpassword", ForgotPassword)
	r.POST("/api/customer/reset-password", ResetPassword)

	r.POST("/api/admin/login", AdminLogin)

	customer := r.Group("/api/customer")
	customer.Use(Auth("customer"))

	customer.GET("/profile", GetProfile)
	customer.PUT("/profile", UpdateProfile)
	customer.GET("/products", GetInventory)
	customer.GET("/products/:id", GetInventoryByID)
	customer.POST("/cart/add", AddToCart)
	customer.GET("/cart", ViewCart)
	customer.PUT("/cart", UpdateCart)
	customer.DELETE("/cart/item", DeleteCartItem)
	customer.POST("/order/place", PlaceOrder)
	customer.GET("/order/history", OrderHistory)
	customer.PATCH("/order/:id/cancel-request", CancelRequest)

	admin := r.Group("/api/admin")
	admin.Use(Auth("admin"))
	admin.GET("/users", GetAllUsers)
	admin.PATCH("/users/:id/status", ChangeUserStatus)
	admin.POST("/product/add", AddItem)
	admin.GET("/products", GetItems)
	admin.GET("/product/:id", GetItem)
	admin.PUT("/product/:id", UpdateItem)
	admin.DELETE("/product/:id", DeleteItem)
	admin.PATCH("/product/:id/disable", DisableItem)
	admin.GET("/orders/pending", GetPendingOrders)
	admin.PATCH("/order/:id/request", DecideOrder)
	admin.GET("/orders/cancel-requests", GetCancelRequests)
	admin.PATCH("/order/:id/cancel", UpdateCancelRequest)
	admin.GET("/orders", GetAllOrders)
	admin.GET("/users/:id/orders", GetUserOrders)

	r.Run(":8000")
}
