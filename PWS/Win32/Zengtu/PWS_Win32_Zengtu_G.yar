
rule PWS_Win32_Zengtu_G{
	meta:
		description = "PWS:Win32/Zengtu.G,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 } //1 SOFTWARE\Borland\Delphi
		$a_00_1 = {57 69 6e 64 6f 77 73 58 50 } //1 WindowsXP
		$a_01_2 = {57 69 6e 64 6f 77 73 32 33 } //1 Windows23
		$a_00_3 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e } //1 Content-Type: application
		$a_00_4 = {55 73 65 72 3d 00 00 00 ff ff ff ff 06 00 00 00 26 50 61 73 73 3d 00 00 ff ff ff ff } //1
		$a_01_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_6 = {53 74 61 72 74 48 6f 6f 6b } //1 StartHook
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}