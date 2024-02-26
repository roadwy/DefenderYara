
rule Trojan_Win32_Rozena_GZC_MTB{
	meta:
		description = "Trojan:Win32/Rozena.GZC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {89 c2 88 84 04 90 01 04 83 e2 1f 8a 54 14 2c 88 54 04 4c 40 3d 90 01 06 31 f6 31 ff 0f b6 84 34 90 01 04 01 f8 02 44 34 4c 0f b6 f8 8d 84 24 90 01 04 01 f0 46 89 44 24 04 8d 84 24 90 01 04 01 f8 89 04 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}