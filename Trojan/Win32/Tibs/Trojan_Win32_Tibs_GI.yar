
rule Trojan_Win32_Tibs_GI{
	meta:
		description = "Trojan:Win32/Tibs.GI,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {fd 8b 06 48 83 c6 fc 35 90 01 04 50 8f 46 04 83 ee fd e2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}