
rule Trojan_BAT_Bladabindi_RPK_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.RPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {77 00 77 00 77 00 2e 00 75 00 70 00 6c 00 6f 00 6f 00 64 00 65 00 72 00 2e 00 6e 00 65 00 74 00 90 02 80 2e 00 74 00 78 00 74 00 90 00 } //1
		$a_01_1 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 53 00 74 00 72 00 69 00 6e 00 67 00 } //1 DownloadString
		$a_01_2 = {43 6f 6e 76 65 72 74 } //1 Convert
		$a_01_3 = {4c 61 74 65 47 65 74 } //1 LateGet
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_5 = {49 6e 76 6f 6b 65 } //1 Invoke
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}