
rule Trojan_BAT_Burkina_A_MTB{
	meta:
		description = "Trojan:BAT/Burkina.A!MTB,SIGNATURE_TYPE_PEHSTR,15 00 15 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 41 41 41 34 41 67 76 59 43 } //10 AAAA4AgvYC
		$a_01_1 = {41 45 41 41 41 41 41 41 41 49 73 34 48 } //10 AEAAAAAAAIs4H
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {52 65 76 65 72 73 65 53 74 72 69 6e 67 } //1 ReverseString
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=21
 
}