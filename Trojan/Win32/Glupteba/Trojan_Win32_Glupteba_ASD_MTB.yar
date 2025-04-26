
rule Trojan_Win32_Glupteba_ASD_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.ASD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 0a 00 00 "
		
	strings :
		$a_01_0 = {67 65 64 65 76 75 66 69 79 69 6c 69 72 6f 77 69 78 75 6a 61 67 65 64 75 72 6f 62 6f 6c 75 6a 69 73 61 79 69 73 61 64 61 79 61 68 6f 72 69 } //1 gedevufiyilirowixujagedurobolujisayisadayahori
		$a_01_1 = {54 69 64 65 76 65 66 6f 66 6f 67 6f 78 61 20 63 6f 7a 69 76 75 64 75 79 20 78 61 76 65 78 69 78 65 67 75 6b 75 72 65 } //1 Tidevefofogoxa cozivuduy xavexixegukure
		$a_01_2 = {4e 6f 74 6f 72 65 74 61 20 62 65 6a 6f 70 65 62 6f 64 65 6c 75 6b 20 6c 6f 78 69 72 6f 68 69 72 75 62 65 76 65 20 6e 65 62 61 77 69 63 61 6d 65 68 } //1 Notoreta bejopebodeluk loxirohirubeve nebawicameh
		$a_01_3 = {54 69 6c 75 63 75 6b 20 76 65 6a 6f 74 65 73 65 76 69 64 61 67 20 6d 75 6e 61 72 69 6a 61 72 61 78 65 } //1 Tilucuk vejotesevidag munarijaraxe
		$a_01_4 = {54 00 61 00 6a 00 20 00 64 00 61 00 6e 00 20 00 79 00 69 00 76 00 6f 00 77 00 69 00 72 00 6f 00 20 00 67 00 75 00 6a 00 6f 00 6b 00 65 00 6c 00 } //1 Taj dan yivowiro gujokel
		$a_01_5 = {77 75 72 6f 68 65 74 61 70 6f 64 65 72 69 6b 69 62 20 78 75 70 69 6e 20 6d 61 68 65 77 6f 67 } //1 wurohetapoderikib xupin mahewog
		$a_01_6 = {70 6f 73 69 6e 6f 6b 69 7a 75 76 75 76 6f 6e 65 67 65 7a 75 6d 75 62 65 6a 6f 78 20 64 61 72 6f 76 75 7a 65 76 6f 68 61 67 69 6d 75 77 75 72 69 6d 6f 70 6f 6e 69 66 61 67 20 67 65 64 61 67 75 77 65 70 69 64 69 7a 65 77 65 64 61 6a 61 6b 6f 76 6f 63 69 77 6f 67 6f 6d 65 } //1 posinokizuvuvonegezumubejox darovuzevohagimuwurimoponifag gedaguwepidizewedajakovociwogome
		$a_01_7 = {6d 75 72 69 62 75 70 75 6c 75 6c 6f 6d 65 7a 6f 6a 69 6e 6f 76 61 64 69 74 75 6d 61 6c 61 77 20 63 61 66 75 76 69 74 69 72 65 68 69 66 6f 78 69 63 6f 78 75 6e 65 63 65 76 65 79 65 76 6f 74 6f 20 68 65 74 65 74 } //1 muribupululomezojinovaditumalaw cafuvitirehifoxicoxuneceveyevoto hetet
		$a_01_8 = {6d 61 6b 6f 76 61 6b 61 74 75 6a 69 68 65 6d 6f 20 78 69 77 75 76 69 63 61 77 69 66 65 6e 75 66 65 7a 6f 70 65 72 6f 6d 65 77 69 70 69 77 20 77 69 72 6f 76 69 79 69 68 75 64 65 72 65 77 75 6b 65 66 61 76 69 62 69 6e 69 78 75 6b 61 74 75 20 73 65 67 69 72 69 73 61 6d 61 6d 6f 67 6f 64 61 70 61 6d 61 70 75 70 69 76 75 6c 61 63 75 73 } //1 makovakatujihemo xiwuvicawifenufezoperomewipiw wiroviyihuderewukefavibinixukatu segirisamamogodapamapupivulacus
		$a_01_9 = {74 75 68 6f 72 75 62 65 62 69 73 61 79 6f 73 61 6a 69 6e 69 63 65 68 75 6a 61 62 65 76 } //1 tuhorubebisayosajinicehujabev
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=5
 
}