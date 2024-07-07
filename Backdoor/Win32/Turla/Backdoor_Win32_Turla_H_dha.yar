
rule Backdoor_Win32_Turla_H_dha{
	meta:
		description = "Backdoor:Win32/Turla.H!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {30 4c 05 98 40 83 f8 0c 72 f6 } //1
		$a_01_1 = {c7 45 b8 2e 64 6f 63 88 5d bc c7 45 d8 2e 70 64 66 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}