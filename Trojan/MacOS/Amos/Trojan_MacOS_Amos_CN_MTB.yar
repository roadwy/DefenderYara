
rule Trojan_MacOS_Amos_CN_MTB{
	meta:
		description = "Trojan:MacOS/Amos.CN!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e8 53 01 00 00 f6 45 c8 01 75 45 f6 45 98 01 75 4e f6 45 b0 01 75 57 f6 45 80 01 74 09 48 8b 7d 90 e8 14 01 00 00 4c 89 ff e8 0c 01 00 00 4c 89 f7 e8 04 01 00 00 48 89 df e8 fc 00 00 00 31 c0 48 81 c4 b0 00 00 00 } //1
		$a_01_1 = {49 89 c4 f6 45 98 01 74 36 eb 78 49 89 c4 f6 45 b0 01 74 31 eb 7c 49 89 c4 f6 45 80 01 75 2c eb 33 49 89 c4 eb 2e 49 89 c4 eb 31 49 89 c4 eb 34 49 89 c4 f6 45 c8 01 75 3b f6 45 98 01 75 44 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}