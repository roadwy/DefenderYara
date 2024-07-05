
rule Trojan_Win32_Zenpak_GXU_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GXU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {01 c2 8d 05 90 01 04 31 28 89 c2 4a 01 1d 90 01 04 83 ea 90 01 01 31 c2 01 3d 90 01 04 4a 83 c2 90 01 01 b8 90 01 04 8d 05 90 01 04 89 30 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}