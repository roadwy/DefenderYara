
rule Trojan_MacOS_Amos_DL_MTB{
	meta:
		description = "Trojan:MacOS/Amos.DL!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 7d b0 8b 45 a0 89 45 c8 8b 45 cc c1 e0 04 8b 4d c8 09 c8 88 45 c7 0f be 75 c7 e8 5f a9 52 00 e9 00 00 00 00 } //1
		$a_01_1 = {55 48 89 e5 48 83 ec 20 48 89 7d f0 48 8b 7d f0 48 89 7d e0 e8 97 7e 52 00 48 8b 7d e0 48 89 c6 e8 4b 80 52 00 48 89 45 e8 e9 00 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}