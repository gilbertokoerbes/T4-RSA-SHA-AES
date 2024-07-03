// Author: Gilberto Luis Koerbes Junior
// Este código executa a primeira etapa de troca de chaves.
// Nesta etapa, geramos chave publica e privada e as assinamos com a chave publica do professor.
// Váriaveis de entrada: ep e Np (professor) , demais valores são gerados pelo código
// go version go1.18.1 linux/amd64
// para executar sem compilar => go run nome_arquivo

// Valores Utilizados
// p =>  251787653647596111358753594800516051335892412751610684604079837934438285307815007394475113731622174749959146838158342665207495956097474758314432916492507152278848384489421042523715360732327120579014888686092190641041425682406151933510122847862625471432906970511539646671903322972355350217220567223777597535167
// q =>  328071446758118008838795340020837001495527762900187956889166914528655535592500311628448644238784678978187035524222184922918424346816151497804735889102814500783022268440673573866828809784767753523439968562672730839454067087415023151679167155474474023074603608017047990271511853770992473455950011390019872720789
// Na =>  82604339807998785310951125090131951286436811847422455702487266102549909471617066967663795059775871595200542163840853343386017613496722610892520660824135169792825987339994476684970530285128757206915598741108598033126622564990612311269966454663188357314611423928162731333915405455933899983873125065451953476805226529817697655922407683671971612614341973802382244672249920172674458351367969966820563521228948011478931663559126191708497704746896819705673187814588216687225999972752019335429965679391380317830454450146205657719948398160987989909301922488389880139607529059530175812246667352323207809295912629779588399486763
// L =>  82604339807998785310951125090131951286436811847422455702487266102549909471617066967663795059775871595200542163840853343386017613496722610892520660824135169792825987339994476684970530285128757206915598741108598033126622564990612311269966454663188357314611423928162731333915405455933899983873125065451953476804646670717291941802210134737150259561510553626730446030756673420211364530467654647797639763258541157750785481196745664120371784443983193449554019008992895034164129319821924719039421508874285443727999592897440736239452905391166814824112632485052780645100018481001588175303252175579859985622742051165790929230808
// ea =>  21267647932558653966460912964485513219
// da =>  26760919176091449249796408278552586392472210735888353461302465871800228031577817813091925518341173421712951563336417453709321826827386708223573969200581371544827099789706353242044942254050641317115705459299310239687385191659003867285784022434891972304721679416774915264345318131334513756346701171858610461006909668687272596349740488789929902674337433377036210179083168208345216058938186957574379229050675949079794932107667849453290595539140899881894949701345177284273594309884414683392130360854462006516832501773157536475240162230760344202343009005176232915763920942571291416589357012415106678054019811260469512633659
// da_hex => D3FCC099E6E4DAE711B83135CA8021831FDAE8B427340308716D06C01302BBC2248B66A123216ECD341164D1F89662DE53FB68A3F042A70F1F7F3CFFBA0AFCC3894087A5BC9AA1A59D18E393CB8E0AA7E6213A597DBE7713ADD8CD1088D318A6B6552C72423E256DBA4AFD636AD5E1E8FE81D89085A37CD7A59B1DB2B72A026F31DB8D06CA41BCFB23958862E8761B60632A7D7BECB9844BFAF291B853E1F483661FFDB6038434EC024BB5428EA840C31CBC1FB5E3752BB5E40081C5E816B1F04FCEEDFD4F8D68CF20956462FF50278412FFC24F03771A47663B1C6F074EDBF64832B2D8ABF2ED1681C2C7AC06E340B340F56FAD868B419152D663C1E1C9FD3B
// 
// pka(ea, Na => ( 21267647932558653966460912964485513219  ,  82604339807998785310951125090131951286436811847422455702487266102549909471617066967663795059775871595200542163840853343386017613496722610892520660824135169792825987339994476684970530285128757206915598741108598033126622564990612311269966454663188357314611423928162731333915405455933899983873125065451953476805226529817697655922407683671971612614341973802382244672249920172674458351367969966820563521228948011478931663559126191708497704746896819705673187814588216687225999972752019335429965679391380317830454450146205657719948398160987989909301922488389880139607529059530175812246667352323207809295912629779588399486763 )
// ska(da, Na => ( 26760919176091449249796408278552586392472210735888353461302465871800228031577817813091925518341173421712951563336417453709321826827386708223573969200581371544827099789706353242044942254050641317115705459299310239687385191659003867285784022434891972304721679416774915264345318131334513756346701171858610461006909668687272596349740488789929902674337433377036210179083168208345216058938186957574379229050675949079794932107667849453290595539140899881894949701345177284273594309884414683392130360854462006516832501773157536475240162230760344202343009005176232915763920942571291416589357012415106678054019811260469512633659  ,  82604339807998785310951125090131951286436811847422455702487266102549909471617066967663795059775871595200542163840853343386017613496722610892520660824135169792825987339994476684970530285128757206915598741108598033126622564990612311269966454663188357314611423928162731333915405455933899983873125065451953476805226529817697655922407683671971612614341973802382244672249920172674458351367969966820563521228948011478931663559126191708497704746896819705673187814588216687225999972752019335429965679391380317830454450146205657719948398160987989909301922488389880139607529059530175812246667352323207809295912629779588399486763 )
// 
// s_hex =>  111BFCCB36D9D915AFC8F9E6B0C36664
// x =>  1040403858461990597646745503709926307641562982630131707759177773130590130620577949071168497467406512660625648889099741011051443862558302134509473584562447016379067946744625452239895525742779303994232834895905114657333907625456421195099738720065843908619326452306580125183645547959633926254326909452579732402036596494606610736235977785205954576385855913244234247954004429339812211078231234666448060583188083881266554492938246821652448282208381681781986825436690526230496764973467938301556154271859113401567777757907301707682502260355731557589381752624992980198069969564481549986858737523410567425945618206146667806583
// sigx =>  34646977856312567987389282600400905235910904644658538943763823237464172620857413881216314851763796823890286433448118360906761827105729301152891111573761863248539690764259756004115541599367479327039671340266636947218546749907291815722838480707484160858596923160975039012944127654455438299342692363432482032090916423852581139311100792722922804925676318660007765510655494894688553968264983220461172598815777223088367826968113699039098112927644422429184294408266760621549026950699057972020151010132628744969707988545444309117403005838297565889765416638804540996344133788983960912557114210267305897385971821133742904697680
// x, sigx, pka
// x, sigx, (ea, Na)
// (83DD8960B7E8370A6C70C84B1DE8E847CBBCF31FB01493DBD761CE64E1FE22D37AE1955549C6EBCA8D6B505397D29A031CD543EE2B922157218D02542BBD04475894444A525B5BD9D9B0A7B411FC9641CA467412567DE7FBC52919FB864C0D72FBEA2413F8F07E8A9E43A4109E86CB9C1431E1CB0E36701021677C6839AEA573F743D1C71AB5569334E3960464F8E1FDAB6FBA31BDAE6C5DD7F3C5B69C3615F145E3AB0EDF2430BBCB7A5305FC80EE87C10C7A759BB380C56B04CE83BDCE561FDAB3FB9E64EF9AFACB84CBE87069374BBC9FEE95FCEC7EFFA76B731E4FE2BF28354DF781D0ACCEB999E51601BFF5E7D2CD2FDDC0B99BEF443197BB870DCFF77,11274F97B7723BE5A911E9A09C37B4624F2F736BB6B36EC9922C82D7FB5B39C56BF4C944E6BB8AFF73E731AA9579EE8A64AD5E97344A14F2003326E4B12341C55BC6D31B806C3A8D3C089F31D1494689DB7F60E3E714C81628C082B31B6740EDE4258D87A9B4735174C012F2CDA2665A9B6956B4C0174A5B0D684728D981E2E59371FB063F3A8AE272D5736C209D58FA13955FDCA11B86062EC61C8E64A4939B7B48BD456D358F7F23BA62536BAF5CFBC289618F8E655D2AAA8A8EEF3AE8CC1D23E57F132573AD3404A00DA938DEAB7A3ECF78BDB794F2AA9A9A300F42F3F9E871A06076AC3980958627C2ABB92FEA4568A98A74718BA7E6411D3831FE2D7E350,(10000000000000000000000000000003,28E5A37EA43FA6A6B3A2FB2A5518C15EDF1B24B8D6554AF457D5B8551834F5F2195AB60AA8CF03858A04AB56E1411C8CCEA62F7606E9A59CD2CB6EEAE9CD5059F3D704605C58F4797C6CBC172187224B0E261C338E45EC39CCFCC6CFADE868AB0F94031C95A65C184C954A60F3C7440978FE7594EF04C4FB82B4DCE9C85053DDFDCFDA7D5D25885A00419A009A5606341A964EF76C1886714B3B3A7DCE404CAECC3E22A7DE748C6217F0AEF7430F3925F0D63D27D07415F717441EFE2F992FEA121346076320A2B6D54E9A8F1795696EDF3F1C663C885E3B6B8D1B2699261735CA0E8482BF54D027B07EC143838138DAF5F275D379A42C52180AF526AECF7D72B))


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

	//Gerar primo p
	p := new(big.Int)
	p, err := generate_prime()
	if err != nil {
		fmt.Println("Erro ao gerar número primo:", p, err)
	}

	//Gerar primo q
	q := new(big.Int)
	q, err = generate_prime()
	if err != nil {
		fmt.Println("Erro ao gerar número primo:", p, err)
	}

	//Calcular N = p * q
	Na := new(big.Int)
	Na.Mul(p, q)
	Na_hex := fmt.Sprintf("%X", Na)

	//(p-1)
	p_sub_1 := new(big.Int)
	p_sub_1.Sub(p, big.NewInt(1))
	//(q-1)
	q_sub_1 := new(big.Int)
	q_sub_1.Sub(q, big.NewInt(1))
	// L = (p-1)*(q-1)
	L := new(big.Int)
	L.Mul(p_sub_1, q_sub_1)

	// Inicializar e e uma variável para armazenar o MDC
	ea := new(big.Int) // e aluno
	gcd := new(big.Int)

	// Encontrar o valor de e cujo MDC com L seja 1
	ea.SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16) // inicializa 'e' com 31 bytes, para forçar que seja um 'e' maior. Iniciando em zero estava encontrando em valores muito baixos
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
