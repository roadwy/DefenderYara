
rule Backdoor_Win32_Comfoo_C{
	meta:
		description = "Backdoor:Win32/Comfoo.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 03 00 "
		
	strings :
		$a_03_0 = {50 57 53 56 ff 15 90 01 04 85 c0 74 0f 81 fb 08 21 22 00 75 07 c7 45 90 01 01 01 00 00 00 c7 45 90 01 01 ff ff ff ff e8 90 01 02 00 00 90 00 } //01 00 
		$a_01_1 = {54 48 49 53 33 32 34 4e 45 57 47 41 4d 45 } //01 00  THIS324NEWGAME
		$a_01_2 = {70 65 72 66 64 69 2e 69 6e 69 } //01 00  perfdi.ini
		$a_01_3 = {5c 75 73 62 61 6b 2e 73 79 73 } //01 00  \usbak.sys
		$a_01_4 = {5c 5c 2e 5c 44 65 76 43 74 72 6c 4b 72 6e 6c } //00 00  \\.\DevCtrlKrnl
	condition:
		any of ($a_*)
 
}