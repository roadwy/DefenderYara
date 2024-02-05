
rule Trojan_Win32_SmokeLoader_CST_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b d6 c1 ea 90 01 01 03 d5 8d 04 37 31 44 24 90 01 01 c7 05 90 01 08 c7 05 90 01 08 89 54 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 01 01 8b 0d 90 01 04 81 f9 90 01 04 74 90 01 01 81 c7 90 01 04 ff 4c 24 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}