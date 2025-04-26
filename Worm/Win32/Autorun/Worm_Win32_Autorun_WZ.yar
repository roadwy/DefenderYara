
rule Worm_Win32_Autorun_WZ{
	meta:
		description = "Worm:Win32/Autorun.WZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {f4 64 eb 6e 18 ff b3 f4 01 eb ab fb e6 } //1
		$a_03_1 = {f5 69 00 00 00 04 ?? fe 0a ?? ?? ?? ?? 04 ?? fe fb ef ?? fe f5 6e 00 00 00 04 84 fe 0a ?? ?? ?? ?? 04 ?? fe fb ef ?? fe f5 66 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}