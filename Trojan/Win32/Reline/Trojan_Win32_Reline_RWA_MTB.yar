
rule Trojan_Win32_Reline_RWA_MTB{
	meta:
		description = "Trojan:Win32/Reline.RWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 77 6e 7a 70 75 90 01 01 8b 45 90 01 01 0f b6 04 06 89 45 90 01 01 8b 45 90 01 01 01 c8 89 45 90 01 01 b8 db 35 2d b0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}