
rule Backdoor_Win32_Havar_B{
	meta:
		description = "Backdoor:Win32/Havar.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 61 76 2d 52 61 74 3a 20 } //01 00  Hav-Rat: 
		$a_01_1 = {2d 20 4c 69 62 54 68 65 6d 65 20 56 65 72 73 69 6f 6e } //01 00  - LibTheme Version
		$a_01_2 = {53 48 47 65 74 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 4c 6f 63 61 74 69 6f 6e } //01 00  SHGetSpecialFolderLocation
		$a_01_3 = {53 65 72 76 65 72 20 73 75 63 63 65 73 66 75 6c 6c 79 20 63 72 65 61 74 65 64 20 69 6e 20 63 75 72 72 65 6e 74 20 64 69 72 65 63 74 6f 72 79 } //01 00  Server succesfully created in current directory
		$a_01_4 = {53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 4b 65 79 62 6f 61 72 64 20 4c 61 79 6f 75 74 73 5c 25 2e 38 78 } //01 00  System\CurrentControlSet\Control\Keyboard Layouts\%.8x
		$a_01_5 = {53 65 72 76 65 72 20 63 72 65 61 74 6f 72 20 73 74 61 72 74 65 64 2e 2e 2e 2e } //00 00  Server creator started....
	condition:
		any of ($a_*)
 
}