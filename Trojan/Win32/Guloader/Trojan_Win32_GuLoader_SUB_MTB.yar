
rule Trojan_Win32_GuLoader_SUB_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SUB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {5c 73 63 65 70 74 72 79 5c 64 65 63 69 62 65 6c 73 5c 70 72 69 73 6b 6c 61 73 73 65 72 } //1 \sceptry\decibels\prisklasser
		$a_81_1 = {5c 72 65 73 65 72 76 65 6f 66 66 69 63 65 72 65 72 73 2e 6a 70 67 } //1 \reserveofficerers.jpg
		$a_81_2 = {5c 6b 75 6e 73 74 66 72 64 69 67 74 2e 6c 6e 6b } //1 \kunstfrdigt.lnk
		$a_81_3 = {5c 43 6f 74 79 6c 6f 70 68 6f 72 6f 75 73 5c 43 61 6c 76 69 6e 69 73 74 65 6e 2e 7a 69 70 } //1 \Cotylophorous\Calvinisten.zip
		$a_81_4 = {5c 61 66 66 75 74 61 67 65 72 5c 62 6f 75 67 61 69 6e 76 69 6c 6c 61 65 61 73 2e 69 6e 69 } //1 \affutager\bougainvillaeas.ini
		$a_81_5 = {50 72 6f 68 75 6d 61 6e 69 73 74 69 63 31 2e 73 69 6c } //1 Prohumanistic1.sil
		$a_81_6 = {63 61 72 61 76 61 6e 69 73 74 2e 6d 65 6d } //1 caravanist.mem
		$a_81_7 = {72 65 64 61 6b 74 72 65 6e 2e 66 72 69 } //1 redaktren.fri
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}