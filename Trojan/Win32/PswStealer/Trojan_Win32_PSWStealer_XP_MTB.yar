
rule Trojan_Win32_PSWStealer_XP_MTB{
	meta:
		description = "Trojan:Win32/PSWStealer.XP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 55 d4 69 d2 90 01 04 89 55 d4 c6 45 90 01 01 01 c6 45 90 01 02 c6 45 90 01 01 01 0f bf 45 9c 35 90 01 04 66 89 45 9c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}