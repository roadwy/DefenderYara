
rule Worm_Win32_Autorun_QG{
	meta:
		description = "Worm:Win32/Autorun.QG,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {1c 1b 00 1b 4b 00 43 74 ff 1e fb 01 6c 70 ff f5 02 00 00 00 c7 1c 30 00 1b 4c 00 43 74 ff 1e fb 01 6c 70 ff f5 03 00 00 00 c7 1c 45 00 1b 4d 00 43 74 ff 1e } //1
		$a_01_1 = {41 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 } //1 Autorun.inf
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}