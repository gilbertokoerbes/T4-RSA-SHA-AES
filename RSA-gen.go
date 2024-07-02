package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

func generate_prime() (*big.Int, error) {

	// Define o número de bits desejados (1024 bits neste exemplo, 1025 para gerar)
	numBits := 1025
	randomNumber := new(big.Int)
	var err error

	for true {
		// Gera um número aleatório provavel primo com o número desejado de bits
		randomNumber, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(numBits)))
		if err != nil {
			fmt.Println("Erro ao gerar número aleatório:", err)
		}

		// Verifica se o número gerado é maior que 2^1024
		if randomNumber.Cmp(new(big.Int).Lsh(big.NewInt(1), 1024)) <= 0 {
			//return big.NewInt(1), errors.New("O número gerado não é maior que 2^1024")
			continue
		}
		// Verifica se o número é 0
		if randomNumber.Cmp(big.NewInt(0)) == 0 {
			//fmt.Println("O número gerado é 0")
			continue
		}

		//Validar teste se 2^(p-1) = 1 em Zp
		p_sub_1 := new(big.Int)
		p_sub_1.Sub(randomNumber, big.NewInt(1))
		validate_prime := new(big.Int)
		validate_prime.Exp(big.NewInt(2), p_sub_1, randomNumber)

		if validate_prime.Cmp(big.NewInt(1)) == 0 {
			return randomNumber, nil
		}
	}

	return big.NewInt(1), errors.New("Não encontrado")
}

func main() {

	p := new(big.Int)
	p, err := generate_prime()
	if err != nil {
		fmt.Println("Erro ao gerar número primo:", p, err)
	}

	//Gerar primo p
	q := new(big.Int)
	q, err = generate_prime()
	if err != nil {
		fmt.Println("Erro ao gerar número primo:", p, err)
	}

	//Calcular N = p * q
	Na := new(big.Int)
	Na.Mul(p, q)
	Na_hex := fmt.Sprintf("%X", Na)

	p_sub_1 := new(big.Int)
	p_sub_1.Sub(p, big.NewInt(1))

	q_sub_1 := new(big.Int)
	q_sub_1.Sub(q, big.NewInt(1))

	L := new(big.Int)
	L.Mul(p_sub_1, q_sub_1)

	// Inicializar e e uma variável para armazenar o MDC
	ea := new(big.Int) // e aluno
	gcd := new(big.Int)

	// Encontrar o valor de e cujo MDC com L seja 1
	ea.SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16) // inicializa 'e' com 31 bytes, para encontrar um 'e' maior
	for {
		gcd.GCD(nil, nil, ea, L)
		if gcd.Cmp(big.NewInt(1)) == 0 {
			break
		}
		ea.Add(ea, big.NewInt(1))
	}
	ea_hex := fmt.Sprintf("%X", ea)

	// Encontrar o inverso de e módulo L
	da := new(big.Int) // d aluno
	da.ModInverse(ea, L)

	// Verificar se o inverso foi encontrado
	if da == nil {
		fmt.Println("Inverso não encontrado")
	}

	// Gerar um primo randomico de 1024 bits e pegar 128 bits para chave AES
	random_prime := new(big.Int)
	random_prime, err = generate_prime()

	// Obter 32 bytes
	s_hex := fmt.Sprintf("%X", random_prime)[:32]
	fmt.Println(s_hex)

	// Parse hexadecimal string to big.Int
	s_decimal := new(big.Int)
	s_decimal.SetString(s_hex, 16)

	//e professor
	ep := new(big.Int)
	ep.SetString("2E76A0094D4CEE0AC516CA162973C895", 16)

	// N professor
	Np := new(big.Int)
	Np_hex := "1985008F25A025097712D26B5A322982B6EBAFA5826B6EDA3B91F78B7BD63981382581218D33A9983E4E14D4B26113AA2A83BBCCF" +
		"DE24310AEE3362B6100D06CC1EA429018A0FF3614C077F59DE55AADF449AF01E42ED6545127DC1A97954B89729249C6060BA4BD3A5" +
		"9490839072929C0304B2D7CBBA368AEBC4878A6F0DA3FE58CECDA638A506C723BDCBAB8C355F83C0839BF1457A3B6B89307D672BB" +
		"F530C93F022E693116FE4A5703A665C6010B5192F6D1FAB64B5795876B2164C86ABD7650AEDAF5B6AFCAC0438437BB3BDF5399D80F" +
		"8D9963B5414EAFBFA1AA2DD0D24988ACECA8D50047E5A78082295A987369A67D3E54FFB7996CBE2C5EAD794391"
	Np.SetString(Np_hex, 16)

	//x	=	s^ep mod Np
	x := new(big.Int).Exp(s_decimal, ep, Np)
	x_hex := fmt.Sprintf("%X", x)

	// sigx =	xda mod	Na
	sigx := new(big.Int).Exp(x, da, Na)
	sigx_hex := fmt.Sprintf("%X", sigx)

	// Exibe resultados:
	fmt.Println("p => ", p)
	fmt.Println("q => ", q)
	fmt.Println("Na => ", Na)
	fmt.Println("L => ", L)
	fmt.Println("ea => ", ea)
	fmt.Println("da => ", da)
	fmt.Println()
	fmt.Println("pka(ea, Na => (", ea, " , ", Na, ")")
	fmt.Println("ska(da, Na => (", da, " , ", Na, ")")
	fmt.Println()
	fmt.Println("s_hex => ", s_hex)
	fmt.Println("x => ", x)
	fmt.Println("sigx => ", sigx)
	fmt.Println("x, sigx, pka")
	fmt.Println("x, sigx, (ea, Na)")
	fmt.Printf("(%s,%s,(%s,%s))", x_hex, sigx_hex, ea_hex, Na_hex)

}
