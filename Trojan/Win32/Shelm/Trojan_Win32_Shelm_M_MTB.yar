
rule Trojan_Win32_Shelm_M_MTB{
	meta:
		description = "Trojan:Win32/Shelm.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {0f b6 c8 88 84 3d 90 01 04 0f b6 84 35 90 01 04 03 c8 0f b6 c1 8b 8d d8 90 01 03 0f b6 84 05 90 01 04 32 44 13 90 01 01 88 04 0a 42 81 fa 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}