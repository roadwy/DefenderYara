
rule Worm_Win32_Dodinsom_A{
	meta:
		description = "Worm:Win32/Dodinsom.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {f5 2e 00 00 00 04 a4 fe 0a 90 01 01 00 08 00 04 90 01 01 fe fb ef 90 01 01 fe f5 73 00 00 00 04 90 01 01 fe 0a 90 01 01 00 08 00 04 90 01 01 fe fb ef 90 01 01 fe f5 77 00 00 00 04 90 01 01 fe 0a 90 01 01 00 08 00 04 90 01 01 fe fb ef 90 01 01 fe f5 66 00 00 90 00 } //01 00 
		$a_03_1 = {f4 14 eb 6e 90 01 01 ff b3 f4 01 eb ab fb e6 fb ff 90 00 } //01 00 
		$a_01_2 = {f5 01 00 00 00 c5 f5 02 00 00 00 c5 f5 04 00 00 00 c5 f5 20 00 00 00 c5 } //00 00 
	condition:
		any of ($a_*)
 
}