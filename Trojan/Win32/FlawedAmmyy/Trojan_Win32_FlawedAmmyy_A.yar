
rule Trojan_Win32_FlawedAmmyy_A{
	meta:
		description = "Trojan:Win32/FlawedAmmyy.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 45 ec 83 c0 01 89 45 ec 8b 4d ec 3b 4d fc 73 26 8b 55 ec 81 f2 ff 00 00 00 83 c2 2d 89 55 e8 8b 45 ec 0f b6 88 90 01 04 33 4d e8 8b 55 f0 03 55 ec 88 0a eb c9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}