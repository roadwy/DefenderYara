
rule Trojan_Win32_SpyStealer_XK_MTB{
	meta:
		description = "Trojan:Win32/SpyStealer.XK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b c8 8b 45 fc 99 33 c1 89 45 fc 8b 55 0c 89 55 08 8b 45 fc 89 45 0c 8b 4d 08 03 4d 0c 89 4d f4 8b 45 f4 8b e5 } //00 00 
	condition:
		any of ($a_*)
 
}