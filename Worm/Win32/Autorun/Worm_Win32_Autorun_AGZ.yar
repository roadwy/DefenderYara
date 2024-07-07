
rule Worm_Win32_Autorun_AGZ{
	meta:
		description = "Worm:Win32/Autorun.AGZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {5c 73 65 63 72 65 74 2e 65 78 65 90 02 10 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 90 00 } //1
		$a_02_1 = {5c 5c 31 39 32 2e 31 36 38 2e 30 2e 90 02 03 5c 73 65 63 72 65 74 2e 65 78 65 90 02 03 5c 5c 31 39 32 2e 31 36 38 2e 30 2e 90 02 03 5c 73 65 63 72 65 74 2e 65 78 65 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}