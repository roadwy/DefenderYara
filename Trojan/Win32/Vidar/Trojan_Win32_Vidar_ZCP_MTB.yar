
rule Trojan_Win32_Vidar_ZCP_MTB{
	meta:
		description = "Trojan:Win32/Vidar.ZCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c6 0f b6 c0 0f b6 44 04 90 01 01 30 04 3a 8b 54 24 18 85 d2 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}