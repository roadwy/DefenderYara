
rule Worm_Win32_Autorun_DQ{
	meta:
		description = "Worm:Win32/Autorun.DQ,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {66 75 63 6b 2e 72 65 67 } //1 fuck.reg
		$a_02_1 = {43 3a 5c 77 69 6e 64 6f 77 73 5c 54 65 6d 70 5c [0-08] 2e 74 78 74 } //1
		$a_02_2 = {43 3a 5c 77 69 6e 64 6f 77 73 5c 54 65 6d 70 5c [0-08] 2e 65 78 65 } //1
		$a_00_3 = {41 75 74 6f 72 75 6e 2e 69 6e 66 } //1 Autorun.inf
		$a_00_4 = {6b 77 61 74 63 68 2e 65 78 65 } //1 kwatch.exe
		$a_00_5 = {6b 76 73 72 76 78 70 2e 65 78 65 } //1 kvsrvxp.exe
		$a_00_6 = {56 50 54 72 61 79 2e 65 78 65 } //1 VPTray.exe
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}