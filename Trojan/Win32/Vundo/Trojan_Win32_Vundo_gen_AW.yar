
rule Trojan_Win32_Vundo_gen_AW{
	meta:
		description = "Trojan:Win32/Vundo.gen!AW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 11 39 55 08 73 05 89 55 08 8b c7 47 83 c1 10 3b fb 72 90 01 01 83 f8 ff 74 90 01 01 c1 e0 04 03 c6 33 ff 90 00 } //01 00 
		$a_01_1 = {8b 45 d4 6a 00 2b ce 68 80 96 98 00 1b c2 50 51 } //00 00 
	condition:
		any of ($a_*)
 
}