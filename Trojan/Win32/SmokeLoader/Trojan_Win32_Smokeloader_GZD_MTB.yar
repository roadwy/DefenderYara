
rule Trojan_Win32_Smokeloader_GZD_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GZD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {6b 00 65 00 c7 05 90 01 04 72 00 6e 00 c7 05 90 01 04 65 00 6c 00 c7 05 90 01 04 33 00 32 00 c7 05 90 01 04 2e 00 64 00 c7 05 90 01 04 6c 00 6c 00 66 a3 90 01 04 ff 15 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Smokeloader_GZD_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.GZD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c7 89 45 90 01 01 8b 45 90 01 01 c1 e8 90 01 01 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 33 d2 c7 05 90 01 04 ee 3d ea f4 89 45 90 01 01 89 55 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 31 45 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}