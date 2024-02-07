
rule Backdoor_Win32_Simda_AT{
	meta:
		description = "Backdoor:Win32/Simda.AT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {2e 64 72 69 76 65 72 00 90 01 20 2e 63 66 67 62 69 6e 00 90 01 20 2e 75 61 63 36 34 00 90 00 } //01 00 
		$a_01_1 = {43 6c 61 73 73 65 73 5c 53 55 50 45 52 41 6e 74 69 53 70 79 77 61 72 65 43 6f 6e 74 65 78 74 4d 65 6e 75 45 78 74 2e 53 41 53 43 6f 6e 2e 31 } //01 00  Classes\SUPERAntiSpywareContextMenuExt.SASCon.1
		$a_01_2 = {57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 45 52 55 4e 54 5f 69 73 31 } //01 00  Windows\CurrentVersion\Uninstall\ERUNT_is1
		$a_03_3 = {6b c0 28 03 85 90 01 02 ff ff 89 85 90 01 02 ff ff 8b 85 90 01 02 ff ff 40 89 45 f8 8b 45 f8 81 38 6e 6c 73 63 90 00 } //00 00 
		$a_00_4 = {7e } //15 00  ~
	condition:
		any of ($a_*)
 
}