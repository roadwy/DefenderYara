
rule Worm_Win32_Autorun_ADL{
	meta:
		description = "Worm:Win32/Autorun.ADL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {ff 15 48 f0 40 00 [0-02] a3 04 10 40 00 } //1
		$a_01_1 = {eb 00 90 52 90 5a } //1
		$a_01_2 = {bb 00 10 40 00 89 db 52 90 5a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}