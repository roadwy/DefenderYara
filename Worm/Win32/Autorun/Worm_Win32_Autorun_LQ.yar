
rule Worm_Win32_Autorun_LQ{
	meta:
		description = "Worm:Win32/Autorun.LQ,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 6f 77 72 70 72 6f 66 00 00 00 00 10 00 00 00 53 65 74 53 75 73 70 65 6e 64 53 74 61 74 65 00 0c 00 00 00 68 00 63 00 75 00 72 00 75 00 6e 00 } //1
		$a_01_1 = {41 00 3a 00 00 00 00 00 04 00 00 00 42 00 3a 00 00 00 00 00 08 00 00 00 66 00 69 00 6c 00 65 00 00 00 00 00 08 00 00 00 57 00 33 00 32 00 2e 00 00 00 00 00 0a 00 00 00 2e 00 57 00 6f 00 72 00 6d 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}