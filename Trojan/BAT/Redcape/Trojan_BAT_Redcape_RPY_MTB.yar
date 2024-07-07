
rule Trojan_BAT_Redcape_RPY_MTB{
	meta:
		description = "Trojan:BAT/Redcape.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {64 00 6f 00 6d 00 61 00 6b 00 6f 00 73 00 6b 00 69 00 6d 00 61 00 64 00 65 00 69 00 72 00 65 00 69 00 72 00 61 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 } //1 domakoskimadeireira.com.br
		$a_01_1 = {52 00 6e 00 70 00 6e 00 6a 00 61 00 6b 00 75 00 2e 00 64 00 6c 00 6c 00 } //1 Rnpnjaku.dll
		$a_01_2 = {46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 } //1 FromBase64String
		$a_01_3 = {41 72 72 61 79 } //1 Array
		$a_01_4 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_5 = {48 74 74 70 43 6c 69 65 6e 74 } //1 HttpClient
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}