
rule Trojan_Win32_Bunitu_PVS_MTB{
	meta:
		description = "Trojan:Win32/Bunitu.PVS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b c0 33 3d 90 01 04 8b cf b8 04 00 00 00 03 c1 83 e8 04 a3 90 01 04 a1 90 01 04 8b 0d 90 01 04 89 08 90 00 } //02 00 
		$a_00_1 = {8b 4d 08 89 31 8b 55 08 8b 02 2d 36 a6 06 00 8b 4d 08 89 01 } //00 00 
	condition:
		any of ($a_*)
 
}