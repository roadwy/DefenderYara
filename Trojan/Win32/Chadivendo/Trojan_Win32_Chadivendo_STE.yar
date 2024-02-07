
rule Trojan_Win32_Chadivendo_STE{
	meta:
		description = "Trojan:Win32/Chadivendo.STE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {50 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 68 90 01 02 01 10 90 01 04 ff 15 90 01 01 e0 00 10 90 02 06 68 90 01 02 01 10 ff 15 90 01 01 e0 00 10 90 00 } //01 00 
		$a_01_1 = {69 c0 01 01 01 01 83 f9 20 0f 86 df 00 00 00 } //01 00 
		$a_00_2 = {53 65 72 76 69 63 65 52 65 73 70 6f 6e 63 65 2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e } //00 00 
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}