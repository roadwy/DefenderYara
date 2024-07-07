
rule Worm_Win32_Autorun_DH{
	meta:
		description = "Worm:Win32/Autorun.DH,SIGNATURE_TYPE_PEHSTR,33 00 32 00 07 00 00 "
		
	strings :
		$a_01_0 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 62 00 61 00 72 00 } //10 explorerbar
		$a_01_1 = {5c 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 } //10 \autorun.inf
		$a_01_2 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //10 UnhookWindowsHookEx
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_01_4 = {49 6e 69 63 69 6f 5c 50 72 6f 67 72 61 6d 61 73 5c 49 6e 69 63 69 6f 5c 73 76 63 68 6f 73 74 2e 45 58 45 } //10 Inicio\Programas\Inicio\svchost.EXE
		$a_01_5 = {5c 00 57 00 4b 00 53 00 4d 00 2e 00 45 00 58 00 45 00 } //1 \WKSM.EXE
		$a_01_6 = {5c 00 44 00 61 00 74 00 61 00 2e 00 74 00 78 00 74 00 } //1 \Data.txt
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=50
 
}