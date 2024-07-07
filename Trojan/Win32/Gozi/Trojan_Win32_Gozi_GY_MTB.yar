
rule Trojan_Win32_Gozi_GY_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {05 8a 1e 01 00 2b 05 90 01 04 a3 90 01 04 0f b7 45 f0 8b 4d 0c 8d 44 01 90 01 01 a3 90 01 04 0f b6 05 90 01 04 8b 0d 90 01 04 8d 44 08 90 01 01 03 05 90 01 04 a3 90 01 04 ff 25 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Gozi_GY_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 fb 2b 3d 90 01 04 03 7c 24 90 01 01 89 3d 90 01 04 8b 44 24 90 01 01 8a d9 2a d8 80 c3 90 01 01 66 0f b6 d3 66 2b 15 90 01 04 81 c6 90 01 04 66 2b d0 0f b7 c2 89 75 00 83 c5 04 83 6c 24 90 01 01 01 89 35 90 01 04 89 44 24 90 01 01 0f 85 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}