
rule Worm_Win32_Autorun_ADL{
	meta:
		description = "Worm:Win32/Autorun.ADL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff 15 48 f0 40 00 90 02 02 a3 04 10 40 00 90 00 } //01 00 
		$a_01_1 = {eb 00 90 52 90 5a } //01 00 
		$a_01_2 = {bb 00 10 40 00 89 db 52 90 5a } //00 00 
	condition:
		any of ($a_*)
 
}