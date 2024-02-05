
rule Trojan_Win32_SmokeLoader_GCG_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GCG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 90 01 01 89 45 08 8d 45 08 50 c7 05 90 01 04 19 36 6b ff e8 90 01 04 8b 4d 90 01 01 8b c6 c1 e0 90 01 01 03 45 e8 03 ce 33 c1 33 45 08 2b f8 81 3d 90 01 08 74 90 01 01 81 45 90 01 01 47 86 c8 61 ff 4d f8 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}