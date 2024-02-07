
rule Worm_Win32_Selemen_A{
	meta:
		description = "Worm:Win32/Selemen.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 5c 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 } //01 00  Windows\CurrentVersion\Run\svchost
		$a_01_1 = {3a 00 5c 00 4c 00 75 00 6e 00 61 00 2e 00 65 00 78 00 65 00 } //01 00  :\Luna.exe
		$a_01_2 = {3a 00 5c 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 61 00 2e 00 65 00 78 00 65 00 } //00 00  :\svchosta.exe
	condition:
		any of ($a_*)
 
}