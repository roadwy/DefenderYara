
rule Trojan_Win32_Smokeloader_GMQ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GMQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b ce c1 e9 90 01 01 03 cd 33 cf 31 4c 24 90 01 01 c7 05 90 01 04 19 36 6b ff c7 05 90 01 08 8b 44 24 90 01 01 29 44 24 90 01 01 8d 44 24 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Smokeloader_GMQ_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.GMQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d3 d3 ea 03 c3 89 45 90 01 01 c7 05 90 01 04 ee 3d ea f4 03 55 90 01 01 8b 45 90 01 01 31 45 90 01 01 33 55 90 01 01 81 3d 90 01 08 89 55 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}