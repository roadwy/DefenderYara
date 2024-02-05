
rule Trojan_Win32_Simda_gen_C{
	meta:
		description = "Trojan:Win32/Simda.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {0f b6 02 35 a0 00 00 00 8b 8d 90 01 04 03 8d 90 01 04 88 01 eb 90 00 } //01 00 
		$a_01_1 = {0f be 02 83 f8 21 74 05 } //01 00 
		$a_01_2 = {2f 6b 6e 6f 63 6b 2e 70 68 70 3f } //01 00 
		$a_01_3 = {21 63 6f 6e 66 69 67 } //00 00 
	condition:
		any of ($a_*)
 
}