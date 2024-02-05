
rule Trojan_Win32_SmokeLoader_FRY_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.FRY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c1 c1 e8 05 03 45 e0 03 fa 33 f8 33 7d 0c } //01 00 
		$a_01_1 = {89 7d f0 8b 45 f0 29 45 fc 89 75 f8 8b 45 e4 01 45 f8 2b 5d f8 ff 4d e8 89 5d f0 } //00 00 
	condition:
		any of ($a_*)
 
}