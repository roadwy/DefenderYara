
rule Trojan_MacOS_Amos_DH_MTB{
	meta:
		description = "Trojan:MacOS/Amos.DH!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 48 83 ec 20 48 89 7d f0 48 8b 7d f0 48 89 7d e8 e8 a7 27 87 00 48 8b 7d e8 48 89 45 e0 e8 5a fe ff ff 48 8b 75 e0 48 8b 7d e8 48 01 c6 e8 4a 29 87 00 48 89 45 f8 48 8b 45 f8 48 83 c4 20 5d c3 } //1
		$a_01_1 = {55 48 89 e5 48 83 ec 20 48 89 7d f0 48 8b 7d f0 48 89 7d e0 e8 f7 27 87 00 48 8b 7d e0 48 89 c6 e8 ab 29 87 00 48 89 45 e8 e9 00 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}