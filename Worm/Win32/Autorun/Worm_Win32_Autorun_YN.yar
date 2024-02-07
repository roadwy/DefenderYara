
rule Worm_Win32_Autorun_YN{
	meta:
		description = "Worm:Win32/Autorun.YN,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 54 00 65 00 6d 00 70 00 49 00 45 00 44 00 61 00 74 00 61 00 2e 00 65 00 78 00 65 00 } //01 00  \TempIEData.exe
		$a_01_1 = {53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 30 00 30 00 31 00 5c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 44 00 69 00 73 00 6b 00 5c 00 45 00 6e 00 75 00 6d 00 } //01 00  SYSTEM\ControlSet001\Services\Disk\Enum
		$a_01_2 = {53 00 68 00 65 00 6c 00 6c 00 5f 00 54 00 72 00 61 00 79 00 57 00 6e 00 64 00 } //01 00  Shell_TrayWnd
		$a_01_3 = {5c 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 } //00 00  \autorun.inf
	condition:
		any of ($a_*)
 
}