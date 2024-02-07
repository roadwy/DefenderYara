
rule Backdoor_Win32_Bifrose_EF{
	meta:
		description = "Backdoor:Win32/Bifrose.EF,SIGNATURE_TYPE_PEHSTR,20 00 20 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {72 00 67 00 4d 00 77 00 46 00 2e 00 67 00 66 00 43 00 74 00 65 00 4e 00 48 00 } //0a 00  rgMwF.gfCteNH
		$a_01_1 = {6c 00 6c 00 65 00 68 00 53 00 2e 00 74 00 70 00 69 00 72 00 63 00 53 00 57 00 } //0a 00  llehS.tpircSW
		$a_01_2 = {6e 00 75 00 52 00 5c 00 6e 00 6f 00 69 00 73 00 72 00 65 00 56 00 74 00 6e 00 65 00 72 00 72 00 75 00 43 00 5c 00 73 00 77 00 6f 00 64 00 6e 00 69 00 57 00 5c 00 74 00 66 00 6f 00 73 00 6f 00 72 00 63 00 69 00 4d 00 5c 00 65 00 72 00 61 00 77 00 74 00 66 00 6f 00 53 00 5c 00 55 00 43 00 4b 00 48 00 } //01 00  nuR\noisreVtnerruC\swodniW\tfosorciM\erawtfoS\UCKH
		$a_01_3 = {56 42 35 21 36 26 56 42 36 45 53 2e 44 4c 4c } //01 00  VB5!6&VB6ES.DLL
		$a_01_4 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //00 00  ShellExecuteA
	condition:
		any of ($a_*)
 
}