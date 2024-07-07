
rule Trojan_Win32_Smokeloader_CCED_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.CCED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 45 ec c7 05 90 01 08 03 55 90 01 01 8b 45 90 01 01 31 45 90 01 01 33 55 90 01 01 81 3d 90 01 08 89 55 90 00 } //1
		$a_03_1 = {8b c2 d3 e8 8d 3c 13 81 c3 90 01 04 03 45 90 01 01 33 c7 31 45 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}