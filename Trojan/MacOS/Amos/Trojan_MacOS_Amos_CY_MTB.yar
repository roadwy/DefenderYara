
rule Trojan_MacOS_Amos_CY_MTB{
	meta:
		description = "Trojan:MacOS/Amos.CY!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 53 50 48 8b 1f 48 89 37 48 85 db 74 16 48 89 df e8 65 00 00 00 48 89 df 48 83 c4 08 5b 5d e9 75 00 00 00 } //1
		$a_01_1 = {55 48 89 e5 53 50 48 89 f0 48 c1 e8 3e 75 1a 48 89 f3 48 8d 3c b5 00 00 00 00 e8 1b 03 00 00 48 89 da 48 83 c4 08 5b 5d c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}