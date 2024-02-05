
rule Trojan_Win32_SmokeLoader_GTI_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GTI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8d 0c 03 33 4d 0c 89 35 90 01 04 33 cf 89 4d f0 8b 45 90 00 } //0a 00 
		$a_03_1 = {8b c3 c1 e8 90 01 01 03 45 e0 c7 05 90 01 04 19 36 6b ff 33 45 0c 33 f8 89 7d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}