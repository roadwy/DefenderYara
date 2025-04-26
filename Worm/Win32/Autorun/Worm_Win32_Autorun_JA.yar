
rule Worm_Win32_Autorun_JA{
	meta:
		description = "Worm:Win32/Autorun.JA,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 } //1 autorun.inf
		$a_01_1 = {5b 00 41 00 75 00 74 00 6f 00 52 00 75 00 6e 00 5d 00 } //1 [AutoRun]
		$a_01_2 = {4e 00 6f 00 44 00 72 00 69 00 76 00 65 00 54 00 79 00 70 00 65 00 41 00 75 00 74 00 6f 00 52 00 75 00 6e 00 } //1 NoDriveTypeAutoRun
		$a_01_3 = {4f 00 50 00 45 00 4e 00 3d 00 74 00 61 00 69 00 70 00 69 00 6e 00 67 00 } //1 OPEN=taiping
		$a_01_4 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 20 00 68 00 74 00 74 00 70 00 } //1 explorer http
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}