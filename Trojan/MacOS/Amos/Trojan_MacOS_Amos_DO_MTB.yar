
rule Trojan_MacOS_Amos_DO_MTB{
	meta:
		description = "Trojan:MacOS/Amos.DO!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 48 83 ec 20 48 89 7d f8 48 8b 7d f8 48 89 7d f0 e8 b7 79 94 00 a8 01 0f 85 05 00 00 00 e9 12 00 00 00 } //1
		$a_01_1 = {48 8b 7d d8 e8 f8 79 94 00 48 03 45 e8 48 89 45 f8 48 8b 45 f8 48 83 c4 30 5d c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}