
rule Trojan_Win32_Alureon_BD{
	meta:
		description = "Trojan:Win32/Alureon.BD,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {59 6a 0a bf 90 01 04 8b f3 59 33 c0 f3 a6 0f 84 90 00 } //01 00 
		$a_01_1 = {c6 45 f0 e9 ab 56 e8 } //01 00 
		$a_01_2 = {59 59 74 12 83 c6 04 83 fe 04 72 e5 } //01 00 
		$a_01_3 = {74 64 6c 6d 61 73 6b 2e 64 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}