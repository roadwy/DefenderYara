
rule Trojan_Win32_Vidar_NDD_MTB{
	meta:
		description = "Trojan:Win32/Vidar.NDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 ea 03 55 dc 8b 4d d8 89 55 f8 33 d0 8b 45 fc 33 c2 8b 55 90 01 01 2b f8 89 45 fc ff 4d 90 01 01 89 7d f4 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}