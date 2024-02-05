
rule TrojanClicker_Win32_Zirit_Y{
	meta:
		description = "TrojanClicker:Win32/Zirit.Y,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c7 33 d2 bd ff 00 00 00 f7 f5 32 54 31 01 88 14 31 41 47 3b cb 72 e8 5d 6a 3b 56 c6 44 1e ff 00 e8 } //01 00 
		$a_01_1 = {76 23 0f b6 c0 53 89 45 08 8b 45 08 33 d2 bb ff 00 00 00 f7 f3 32 54 31 01 88 14 31 41 ff 45 08 3b cf 72 e5 5b 80 64 3e ff 00 6a 3b } //00 00 
	condition:
		any of ($a_*)
 
}