
rule Trojan_Win32_SmokeLoader_CPY_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b ce c1 e9 90 01 01 03 4c 24 28 8d 04 33 31 44 24 10 c7 05 90 01 08 c7 05 90 01 08 89 4c 24 14 8b 44 24 14 31 44 24 10 2b 7c 24 10 81 c3 90 01 04 ff 4c 24 18 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}