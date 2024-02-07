
rule Trojan_Win32_Wenga_A{
	meta:
		description = "Trojan:Win32/Wenga.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 72 75 6e 64 6c 6c 33 32 2e 65 78 65 } //01 00  hrundll32.exe
		$a_01_1 = {62 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 72 75 6e } //01 00  bSOFTWARE\Microsoft\Windows\currentversion\run
		$a_01_2 = {61 6d 65 67 61 6e 65 77 6e 65 77 64 72 69 76 65 72 } //00 00  ameganewnewdriver
	condition:
		any of ($a_*)
 
}