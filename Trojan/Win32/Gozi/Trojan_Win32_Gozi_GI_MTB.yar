
rule Trojan_Win32_Gozi_GI_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {66 89 45 fc 0f b6 05 90 01 04 8b 0d 90 01 04 8d 84 01 90 01 04 a2 90 01 04 0f b7 45 90 01 01 83 e8 90 01 01 2b 45 90 01 01 0f b7 4d 90 01 01 03 c8 66 89 4d 90 01 01 0f b6 05 90 01 04 83 e8 90 01 01 a3 90 01 04 ff 65 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Gozi_GI_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 c2 fd 03 d3 89 15 90 01 04 8b 10 0f b6 c1 6b c0 90 01 01 00 05 90 01 04 3b fb 90 18 8d 82 90 01 04 8b f9 8b 54 24 90 01 01 81 c7 dc f4 ff ff 83 44 24 90 01 01 04 a3 90 01 04 89 02 8b 15 90 01 04 03 fa 83 6c 24 90 01 01 01 0f 85 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}