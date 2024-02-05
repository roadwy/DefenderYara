
rule Trojan_Win32_SmokeLoader_GBL_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {2b f0 8b c6 c1 e8 05 c7 05 90 01 04 19 36 6b ff 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b c6 c1 e0 90 01 01 03 45 90 01 01 8d 0c 32 33 c1 33 45 90 01 01 50 8d 45 90 01 01 50 e8 90 01 04 81 3d 90 01 08 74 90 01 01 81 c2 90 01 04 ff 4d 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}