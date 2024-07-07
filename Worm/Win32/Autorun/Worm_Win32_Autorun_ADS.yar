
rule Worm_Win32_Autorun_ADS{
	meta:
		description = "Worm:Win32/Autorun.ADS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {ff 15 48 00 41 00 a3 04 10 40 00 } //1
		$a_01_1 = {eb 00 eb 00 90 88 c0 } //1
		$a_01_2 = {bb 00 10 40 00 89 db 52 90 5a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}