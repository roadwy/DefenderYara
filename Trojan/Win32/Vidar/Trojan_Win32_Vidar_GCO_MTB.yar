
rule Trojan_Win32_Vidar_GCO_MTB{
	meta:
		description = "Trojan:Win32/Vidar.GCO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f b6 84 0d 90 01 04 88 84 15 90 01 04 88 9c 0d 90 01 04 0f b6 94 15 90 01 04 8b 8d 90 01 04 0f b6 c3 03 d0 0f b6 c2 0f b6 84 05 90 01 04 30 04 0e 46 8a 85 90 01 04 3b f7 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}