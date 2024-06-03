package service

import (
	"a21hc3NpZ25tZW50/model"
	repo "a21hc3NpZ25tZW50/repository"
	"errors"
	"time"

	"github.com/golang-jwt/jwt"
)

type UserService interface {
	Register(user *model.User) (model.User, error)
	Login(user *model.User) (token *string, err error)
	GetUserTaskCategory() ([]model.UserTaskCategory, error)
}

type userService struct {
	userRepo repo.UserRepository
}

func NewUserService(userRepository repo.UserRepository) UserService {
	return &userService{userRepository}
}

func (s *userService) Register(user *model.User) (model.User, error) {
	dbUser, err := s.userRepo.GetUserByEmail(user.Email)
	if err != nil {
		return *user, err
	}

	if dbUser.Email != "" || dbUser.ID != 0 {
		return *user, errors.New("email already exists")
	}

	user.CreatedAt = time.Now()

	newUser, err := s.userRepo.CreateUser(*user)
	if err != nil {
		return *user, err
	}

	return newUser, nil
}

func (s *userService) Login(user *model.User) (token *string, err error) {
	// Mengambil pengguna dari repository berdasarkan alamat email yang diberikan
	dbUser, err := s.userRepo.GetUserByEmail(user.Email)
	if err != nil {
		return nil, err
	}

	// Memeriksa apakah pengguna ditemukan
	if dbUser.ID == 0 {
		return nil, errors.New("user not found")
	}

	// Memeriksa kecocokan kata sandi
	if dbUser.Password != user.Password {
		return nil, errors.New("wrong email or password")
	}

	// Membuat claims JWT dengan ID pengguna
	claims := &model.Claims{
		UserID: dbUser.ID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 24).Unix(), // Token berlaku selama 24 jam
		},
	}

	// Membuat token JWT
	tokenJWT := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Mengenerate token JWT menjadi string
	tokenString, err := tokenJWT.SignedString(model.JwtKey)
	if err != nil {
		return nil, err
	}

	// Mengembalikan token JWT
	return &tokenString, nil
}

func (s *userService) GetUserTaskCategory() ([]model.UserTaskCategory, error) {
	// Mendapatkan daftar kategori tugas pengguna dari repository
	categories, err := s.userRepo.GetUserTaskCategory()
	if err != nil {
		return nil, err
	}

	return categories, nil
}
