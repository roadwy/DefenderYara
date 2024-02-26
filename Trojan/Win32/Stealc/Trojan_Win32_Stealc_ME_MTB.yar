
rule Trojan_Win32_Stealc_ME_MTB{
	meta:
		description = "Trojan:Win32/Stealc.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b 7d f0 8b 4d f4 8d 04 37 d3 ee 89 45 ec c7 05 90 01 04 ee 3d ea f4 03 75 90 01 01 8b 45 ec 31 45 fc 33 75 fc 81 3d 90 01 04 13 02 00 00 89 75 ec 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}