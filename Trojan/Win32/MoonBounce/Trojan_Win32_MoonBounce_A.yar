
rule Trojan_Win32_MoonBounce_A{
	meta:
		description = "Trojan:Win32/MoonBounce.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 04 03 f0 68 00 20 00 00 ff 76 50 ff 76 34 ff 57 08 } //01 00 
		$a_01_1 = {6a 04 68 00 20 00 00 ff 76 50 50 ff 57 08 } //01 00 
		$a_01_2 = {f7 ff 83 c7 71 6a 07 8d 04 88 8b d0 83 e2 07 c1 e8 03 0f b6 84 30 c8 00 00 00 } //01 00 
		$a_01_3 = {8d 86 e0 01 00 00 50 8d 86 c0 01 00 00 50 8d 86 80 01 00 00 50 8d 86 1c 01 00 00 50 56 e8 } //00 00 
		$a_00_4 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}