
rule Trojan_Win32_VB_CT{
	meta:
		description = "Trojan:Win32/VB.CT,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 08 00 00 0a 00 "
		
	strings :
		$a_00_0 = {41 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 } //0a 00  Autorun.inf
		$a_00_1 = {6f 00 64 00 62 00 63 00 61 00 64 00 33 00 32 00 2e 00 65 00 78 00 65 00 } //0a 00  odbcad32.exe
		$a_00_2 = {4e 00 6f 00 44 00 72 00 69 00 76 00 65 00 54 00 79 00 70 00 65 00 41 00 75 00 74 00 6f 00 52 00 75 00 6e 00 } //0a 00  NoDriveTypeAutoRun
		$a_00_3 = {61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 2a 00 2e 00 74 00 6d 00 70 00 } //01 00  attachment*.tmp
		$a_00_4 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 2e 5c 72 65 63 79 63 6c 65 64 5c } //01 00  shellexecute=.\recycled\
		$a_02_5 = {73 68 65 6c 6c 5c 90 02 04 5c 43 6f 6d 6d 61 6e 64 3d 2e 5c 72 65 63 79 63 6c 65 64 5c 90 00 } //01 00 
		$a_00_6 = {6f 70 65 6e 3d 2e 5c 72 65 63 79 63 6c 65 64 5c } //01 00  open=.\recycled\
		$a_02_7 = {52 00 65 00 63 00 79 00 63 00 6c 00 65 00 64 00 5c 00 90 02 10 2e 00 65 00 78 00 65 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}