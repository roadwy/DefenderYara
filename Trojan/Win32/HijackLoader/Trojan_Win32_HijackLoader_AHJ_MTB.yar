
rule Trojan_Win32_HijackLoader_AHJ_MTB{
	meta:
		description = "Trojan:Win32/HijackLoader.AHJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {51 56 8b f1 68 d8 c5 00 10 e8 90 01 04 8a 4c 24 07 33 c0 89 46 1c 88 4e 20 89 46 24 89 46 28 89 46 2c c7 06 c8 84 00 10 8b c6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}