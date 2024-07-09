
rule Worm_Win32_Autorun_ADU{
	meta:
		description = "Worm:Win32/Autorun.ADU,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 "
		
	strings :
		$a_03_0 = {ff 15 48 f0 40 00 [0-02] a3 04 10 40 00 } //10
		$a_01_1 = {eb 00 90 86 d2 90 89 db } //10
		$a_01_2 = {bb 00 10 40 00 89 db 52 90 5a } //1
		$a_01_3 = {bb 00 10 40 00 89 db cd 03 90 90 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=21
 
}