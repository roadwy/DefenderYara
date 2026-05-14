
rule Trojan_Win64_Vidar_RR_MTB{
	meta:
		description = "Trojan:Win64/Vidar.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 c9 4d 89 f8 44 89 e8 c1 e8 08 44 31 e8 42 88 04 06 42 0f b6 04 06 44 31 e8 44 69 c8 93 01 00 01 69 c0 00 60 32 00 41 c1 e9 13 41 09 c1 0f 31 44 0f b6 e8 45 31 cd 45 8d 78 01 41 81 e7 ff 0f 00 00 83 3d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Vidar_RR_MTB_2{
	meta:
		description = "Trojan:Win64/Vidar.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 69 04 24 41 42 0f 00 49 f7 e6 48 c1 ea 12 48 ff c2 49 89 14 24 0f 31 48 c1 e2 20 48 09 c2 49 31 55 00 49 8b 45 00 48 c1 e0 07 49 8b 55 00 48 c1 ea 0b 48 31 c2 49 89 55 00 49 8b 04 24 49 01 45 00 49 8b 04 24 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}