
rule Worm_Win32_Autorun_ADU{
	meta:
		description = "Worm:Win32/Autorun.ADU,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {ff 15 48 f0 40 00 90 02 02 a3 04 10 40 00 90 00 } //0a 00 
		$a_01_1 = {eb 00 90 86 d2 90 89 db } //01 00 
		$a_01_2 = {bb 00 10 40 00 89 db 52 90 5a } //01 00 
		$a_01_3 = {bb 00 10 40 00 89 db cd 03 90 90 } //00 00 
	condition:
		any of ($a_*)
 
}