
rule Trojan_MacOS_Amos_DC_MTB{
	meta:
		description = "Trojan:MacOS/Amos.DC!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 0f b6 37 40 f6 c6 01 74 06 49 8b 7f 08 eb 04 89 f7 d1 ef 48 39 f9 73 19 48 89 c7 40 f6 c6 01 74 04 49 8b 7f 10 0f b6 34 0f 89 0c b2 48 ff c1 eb ce } //1
		$a_01_1 = {4d 39 f4 74 3f 41 0f b6 04 24 48 8b 4d b8 8b 04 81 85 c0 78 2a 41 c1 e5 06 41 09 c5 41 83 c7 06 41 83 ff 08 7c 19 41 83 c7 f8 44 89 e8 44 89 f9 d3 f8 0f be f0 48 89 df } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}