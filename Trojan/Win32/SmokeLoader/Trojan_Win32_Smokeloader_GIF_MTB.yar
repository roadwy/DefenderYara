
rule Trojan_Win32_Smokeloader_GIF_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GIF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 64 89 45 c4 83 6d 90 01 01 64 8b 45 bc 8a 4d 90 01 01 03 c7 30 08 83 fb 0f 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Smokeloader_GIF_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.GIF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e8 90 01 01 c7 05 90 01 04 19 36 6b ff c7 05 90 01 08 89 44 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8d 0c 2f 31 4c 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 2b 74 24 90 01 01 81 3d 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}