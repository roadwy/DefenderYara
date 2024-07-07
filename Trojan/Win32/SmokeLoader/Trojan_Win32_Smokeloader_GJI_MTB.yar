
rule Trojan_Win32_Smokeloader_GJI_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GJI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e8 90 01 01 03 f7 c7 05 90 01 04 19 36 6b ff c7 05 90 01 08 89 44 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 81 3d 90 01 08 75 90 01 01 8d 4c 24 90 01 01 51 68 90 01 04 ff 15 90 01 04 31 74 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 2b 5c 24 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}