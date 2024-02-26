
rule Trojan_Win32_Shelm_GMS_MTB{
	meta:
		description = "Trojan:Win32/Shelm.GMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 54 24 04 8d 4a 01 0f be c0 89 44 24 04 c1 f8 02 89 c7 83 e7 0f 89 f8 08 02 8b 44 24 04 c1 e0 06 88 42 01 e9 90 01 04 8b 54 24 04 c7 45 90 01 05 0f b6 02 88 45 04 89 d0 29 f0 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}