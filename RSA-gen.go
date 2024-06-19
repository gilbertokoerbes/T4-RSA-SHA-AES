package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

func generate_prime() (*big.Int, error) {
	// Define o número de bits desejados (1025 bits neste exemplo)
	numBits := 1025

	// Gera um número aleatório provavel primo com o número desejado de bits
	randomNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(numBits)))
	if err != nil {
		fmt.Println("Erro ao gerar número aleatório:", err)
	}

	// Verifica se o número gerado é maior que 2^1024
	if randomNumber.Cmp(new(big.Int).Lsh(big.NewInt(1), 1024)) <= 0 {
		return big.NewInt(1), errors.New("O número gerado não é maior que 2^1024")
	}

	//Validar teste se 2^(p-1) = 1 em Zp
	p_sub_1 := new(big.Int)
	p_sub_1.Sub(randomNumber, big.NewInt(1))

	validate_prime := new(big.Int)
	validate_prime.Exp(big.NewInt(2), p_sub_1, randomNumber)

	if validate_prime.Cmp(big.NewInt(1)) != 0 {
		return big.NewInt(1), errors.New("O número gerado não é primo")
	}

	// Imprime o número gerado
	fmt.Println("Número aleatório gerado com mais de 2^1024 bits:", randomNumber)

	return randomNumber, nil
}

func main() {

	p := new(big.Int)
	p, err := generate_prime()
	if err != nil {
		fmt.Println("Erro ao gerar número primo:", p, err)
	}

}
