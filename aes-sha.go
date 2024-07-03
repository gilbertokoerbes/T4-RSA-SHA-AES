// Author: Gilberto Luis Koerbes Junior
// Este código faz parte de 3 / 3 etapas para troca de mensagens.
// Nesta etapa, recebemos uma mensagem, deciframos a mesma, invertemos o conteúdo e criframos novamente
// Principais variveis de entrada: key (calculada na etapa anterior) - ciphertext (mensagem cifrada)
// #Doc: ESTE CÓDIGO É BASEADO NA DOCUMENTAÇÃO OFICIAL GOLANG.
// CODE EXAMPLE https://pkg.go.dev/crypto/cipher#NewCBCDecrypter
// CODE EXAMPLE https://pkg.go.dev/crypto/cipher#NewCBCEncrypter
// go version go1.18.1 linux/amd64
// para executar sem compilar => go run nome_arquivo

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
)

func addPKCS7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	fmt.Println("Padding => ", padding, padText)
	return append(data, padText...)
}

func main() {

	key, _ := hex.DecodeString("111BFCCB36D9D915AFC8F9E6B0C36664")

	ciphertext, _ := hex.DecodeString("6ADD9194F5B574DCC2B1152420934F888F29CCBD62BC50F9F5421AA66EA7C94F57111A228B2C9DB7E5CE029A6206975967D855256668123F51E12748E7054910C642921530C3F8FB448BB327002561A97C71924E0FF62364A376CD6D3B1A1523")

	/////////////////////// Check Signature /////////////////////////////////
	sigc_hex := "02C371B70AA2B95E3EEA2C75D1EFF4D67CBED8A1F067E975157EE2A259026938F0EE17D8ECCD9A0D0E50AF5EF9777CA943C62011B1F7BE694FC23754636B7BF005898C819D6A8FA2974E5116B18E48FF4A83C299335A06C2B5A1618FB216AE5B24CD445109963FA351EF8B78C5F28290AFA5D11957129B318EE07D034CB6E55542264F8CCE2138FD882E39EE9241EB46C2EC114F227BF792E2FC19845DB51F1CEA4AA29EA0498FE42C0CCA7B8BC0BFD17B0BC9D3D313EA8EFD7E32EA39FC7EC9299329C3FE623FA74E4EBE1BF3250C92E5D48659F182F564132144C4993FBD23210C6A49DB37B75B22F2BFD39A43D02A2A2C8CF01D8182AA84B5EE33DCA9FB81"
	sigc_dec := new(big.Int)
	sigc_dec.SetString(sigc_hex, 16)

	//e profesor
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

	h := sha256.New()
	h.Write(ciphertext)
	hc := h.Sum(nil)
	hc_hex := strings.ToUpper(hex.EncodeToString(hc))

	signature := new(big.Int).Exp(sigc_dec, ep, Np)
	signature_hex := fmt.Sprintf("%X", signature)

	fmt.Println("SHA256(c) => ", hc_hex)
	fmt.Println("calculated sig => ", signature_hex)
	if hc_hex == signature_hex {
		fmt.Println("The signature has been verified!")
		fmt.Println()
	} else {
		fmt.Println("Calculated sig != SHA256(c)")
		os.Exit(0)
	}

	/////////////////////////////////////////////////////////////////////
	/////////////////////// D E C R Y P T ///////////////////////////////
	/////////////////////////////////////////////////////////////////////
	//Block, em Golang, define um objeto BlockMode com base na chave, que define os atributos como quantidade de rounds e tamanho de chave
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]        //pegar os primeiros bytes que representam IV
	ciphertext = ciphertext[aes.BlockSize:] //pegar os demais bytes que representam mensagem

	fmt.Println("aes.BlockSize", aes.BlockSize)
	fmt.Println("iv", iv)
	fmt.Println("Mensagem cifrada recebida", ciphertext)
	fmt.Println("Length Mensagem recebida", len(ciphertext))

	if len(ciphertext)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	//Aqui criamos o modo de operação, passando o objeto Block(informações da chave, tamanho de chave e rounds) e o IV
	mode := cipher.NewCBCDecrypter(block, iv)

	deciphertext := ciphertext
	mode.CryptBlocks(deciphertext, ciphertext) //com o modo definido - parametro1: valor onde a mensagem decifrada é gravada, parametro2: mensagem cifrada

	fmt.Println("%s\n Mensagem decifrada recebida => ", string(deciphertext[:]))
	fmt.Println("Length Mensagem decifrada recebida => ", len(deciphertext))

	/////////////////////////////////////////////////////////////////////
	/////////////////////// E N C R Y P T ///////////////////////////////
	/////////////////////////////////////////////////////////////////////

	message := string(deciphertext[:])
	// Inverter a mensagem em texto plano
	r_message := []rune(message)
	for i, j := 0, len(r_message)-1; i < j; i, j = i+1, j-1 {
		r_message[i], r_message[j] = r_message[j], r_message[i]
	}

	reverse_message := []byte(string(r_message))
	fmt.Println("\\n Mensagem Invertida", (string(reverse_message)))
	fmt.Println("\nlen reverse_message", len(string(reverse_message)))

	reverse_message_with_padding := addPKCS7Padding(reverse_message, aes.BlockSize)
	fmt.Println("\n reverse_message_with_padding", reverse_message_with_padding)
	if len(string(reverse_message_with_padding))%aes.BlockSize != 0 {
		panic("plaintext is not a multiple of the block size")
	}

	//generate new IV random
	iv = make([]byte, 16)
	_, err = rand.Read(iv)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("iv = make([]byte, 16)", iv)

	ciphertext_to_send := make([]byte, aes.BlockSize+len(reverse_message_with_padding))
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	mode = cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext_to_send[aes.BlockSize:], reverse_message_with_padding)

	//Add IV in ciphertext_to_send
	for i := 0; i < aes.BlockSize; i++ {
		ciphertext_to_send[i] = iv[i]

	}
	fmt.Println("ciphertext_to_send reverse_message = ", hex.EncodeToString(ciphertext_to_send))

	// Calculate signature
	//d aluno
	da_str := "267609191760914492497964082785525863924722107358883534613024658718002280315778178130919255183411734217129515633364174537093218268273867082" +
		"23573969200581371544827099789706353242044942254050641317115705459299310239687385191659003867285784022434891972304721679416774915264345318131334513756" +
		"34670117185861046100690966868727259634974048878992990267433743337703621017908316820834521605893818695757437922905067594907979493210766784945329059553" +
		"91408998818949497013451772842735943098844146833921303608544620065168325017731575364752401622307603442023430090051762329157639209425712914165893570124" +
		"15106678054019811260469512633659"
	da := new(big.Int)
	da.SetString(da_str, 10)

	// N professor
	Na := new(big.Int)
	Na_hex := "D3FCC099E6E4DAE711B83135CA8021831FDAE8B427340308716D06C01302BBC2248B66A123216ECD341164D1F89662DE53FB68A3F042A70F1F7F3CFFBA0AFCC3894087A5BC9AA1A59D18E393CB8E0AA7E6213A597DBE7713ADD8CD1088D318A6B6552C72423E256DBA4AFD636AD5E1E8FE81D89085A37CD7A59B1DB2B72A026F31DB8D06CA41BCFB23958862E8761B60632A7D7BECB9844BFAF291B853E1F483661FFDB6038434EC024BB5428EA840C31CBC1FB5E3752BB5E40081C5E816B1F04FCEEDFD4F8D68CF20956462FF50278412FFC24F03771A47663B1C6F074EDBF64832B2D8ABF2ED1681C2C7AC06E340B340F56FAD868B419152D663C1E1C9FD3B"
	Na.SetString(Na_hex, 16)

	// Hash mensagem do aluno
	hash := sha256.New()
	hash.Write(ciphertext_to_send)
	hash_a := hash.Sum(nil)

	//Conveter o Hash para BigInt
	hash_big_int := new(big.Int).SetUint64(binary.BigEndian.Uint64(hash_a))
	// Calcular a assinatura com o Hash do aluno
	signature_a := new(big.Int).Exp(hash_big_int, da, Na)
	signature_a_hex := fmt.Sprintf("%X", signature_a)

	fmt.Println("calculated sig => ", signature_a_hex)
}
