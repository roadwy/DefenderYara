
rule Trojan_Win64_Vidar_GX_MTB{
	meta:
		description = "Trojan:Win64/Vidar.GX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 00 e5 41 0f b6 c5 0f b6 44 05 d0 30 04 1e 48 ff c3 } //2
		$a_01_1 = {48 8b 8d b8 21 00 00 48 ff c1 48 8b 85 88 21 00 00 48 39 c1 4c 8b ad c0 21 00 00 0f 84 71 01 00 00 48 89 ce 48 c1 e6 06 48 39 c1 0f 84 d2 03 00 00 48 89 8d b8 21 00 00 4c 01 ee 31 db eb 26 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}