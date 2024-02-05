
rule Worm_Win32_Autorun_WZ{
	meta:
		description = "Worm:Win32/Autorun.WZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {f4 64 eb 6e 18 ff b3 f4 01 eb ab fb e6 } //01 00 
		$a_03_1 = {f5 69 00 00 00 04 90 01 01 fe 0a 90 01 04 04 90 01 01 fe fb ef 90 01 01 fe f5 6e 00 00 00 04 84 fe 0a 90 01 04 04 90 01 01 fe fb ef 90 01 01 fe f5 66 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}