
rule Trojan_MacOS_Amos_EF_MTB{
	meta:
		description = "Trojan:MacOS/Amos.EF!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c1 e3 06 41 0b 58 14 41 8d 44 24 06 41 83 fc 02 7c 36 41 83 c4 fe 44 89 e6 c1 ee 03 ff c6 31 d2 41 83 fc 18 73 2a 41 89 c4 eb 78 89 c8 31 d2 f7 f7 89 d6 49 8b 06 48 8b 04 f0 48 85 c0 } //1
		$a_01_1 = {48 89 cf 48 c1 ef 3e 48 31 cf 48 0f af f8 48 01 f7 48 ff cf 48 89 bc f5 e8 f5 ff ff 48 81 fe 38 01 00 00 74 2a 48 8d 4a 01 49 89 f8 49 c1 e8 3e 49 31 f8 4c 0f af c0 4c 01 c1 49 01 f0 4c 89 84 f5 f0 f5 ff ff 48 83 c2 02 48 83 c6 02 eb b1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}