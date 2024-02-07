
rule PWS_Win32_Lmir_BMO{
	meta:
		description = "PWS:Win32/Lmir.BMO,SIGNATURE_TYPE_PEHSTR_EXT,2a 00 2a 00 08 00 00 0a 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //0a 00  CreateToolhelp32Snapshot
		$a_01_1 = {54 6f 6f 6c 68 65 6c 70 33 32 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //0a 00  Toolhelp32ReadProcessMemory
		$a_00_2 = {57 6f 6f 6f 6c } //0a 00  Woool
		$a_00_3 = {68 74 74 70 3a 2f 2f 65 6b 65 79 2e 73 64 6f 2e 63 6f 6d } //01 00  http://ekey.sdo.com
		$a_00_4 = {5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //01 00  \drivers\etc\hosts
		$a_00_5 = {6b 61 76 2e } //01 00  kav.
		$a_00_6 = {6d 69 72 31 2e 64 61 74 } //01 00  mir1.dat
		$a_00_7 = {77 6f 77 2e } //00 00  wow.
	condition:
		any of ($a_*)
 
}