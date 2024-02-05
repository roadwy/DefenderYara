
rule Trojan_Win32_Sefnit_BW{
	meta:
		description = "Trojan:Win32/Sefnit.BW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 04 37 32 04 19 41 88 06 8b c3 8d 78 01 8a 10 40 84 d2 75 f9 } //01 00 
		$a_01_1 = {62 6f 74 2e 64 6c 6c 00 5f 65 6e 74 72 79 00 } //00 00 
		$a_00_2 = {5f 0d } //00 00 
	condition:
		any of ($a_*)
 
}