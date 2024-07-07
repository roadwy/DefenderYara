
rule Worm_Win32_Autorun_NQ{
	meta:
		description = "Worm:Win32/Autorun.NQ,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 } //1 \autorun.inf
		$a_01_1 = {73 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 3d 00 41 00 62 00 72 00 69 00 72 00 } //1 shell\open=Abrir
		$a_01_2 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 54 00 61 00 73 00 6b 00 4d 00 67 00 72 00 } //1 DisableTaskMgr
		$a_01_3 = {53 00 79 00 73 00 79 00 65 00 72 00 2e 00 } //1 Sysyer.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}