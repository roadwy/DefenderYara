
rule TrojanSpy_Win32_Bancos_AMH{
	meta:
		description = "TrojanSpy:Win32/Bancos.AMH,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6d 00 61 00 69 00 61 00 72 00 61 00 61 00 76 00 69 00 73 00 6f 00 32 00 30 00 31 00 35 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 } //1 maiaraaviso2015@gmail.com
		$a_01_1 = {6f 00 6c 00 69 00 76 00 65 00 69 00 72 00 61 00 2d 00 61 00 6e 00 32 00 30 00 31 00 34 00 40 00 75 00 6f 00 6c 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 } //1 oliveira-an2014@uol.com.br
		$a_01_2 = {65 00 6c 00 69 00 61 00 6e 00 65 00 31 00 30 00 } //1 eliane10
		$a_01_3 = {73 00 6d 00 74 00 70 00 73 00 2e 00 75 00 6f 00 6c 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 } //1 smtps.uol.com.br
		$a_01_4 = {69 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 62 00 61 00 6e 00 6b 00 69 00 6e 00 67 00 63 00 61 00 69 00 78 00 61 00 } //1 internetbankingcaixa
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}