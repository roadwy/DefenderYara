
rule PWS_Win32_Zengtu_E{
	meta:
		description = "PWS:Win32/Zengtu.E,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {7a 68 65 6e 67 74 75 5f 63 6c 69 65 6e 74 } //01 00  zhengtu_client
		$a_00_1 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e } //01 00  Content-Type: application
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 } //01 00  SOFTWARE\Borland\Delphi
		$a_00_3 = {73 65 6e 64 6d 61 69 6c 2e 61 73 70 } //01 00  sendmail.asp
		$a_01_4 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  ReadProcessMemory
		$a_00_5 = {26 50 61 73 73 3d } //00 00  &Pass=
	condition:
		any of ($a_*)
 
}