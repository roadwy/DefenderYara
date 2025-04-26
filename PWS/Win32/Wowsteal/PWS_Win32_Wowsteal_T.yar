
rule PWS_Win32_Wowsteal_T{
	meta:
		description = "PWS:Win32/Wowsteal.T,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {57 6f 72 6c 64 20 6f 66 20 57 61 72 63 72 61 66 74 } //1 World of Warcraft
		$a_00_1 = {47 78 57 69 6e 64 6f 77 43 6c 61 73 73 44 33 64 } //1 GxWindowClassD3d
		$a_01_2 = {26 70 61 73 73 3d } //1 &pass=
		$a_00_3 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 } //1 SOFTWARE\Borland\Delphi
		$a_00_4 = {41 64 6a 75 73 74 54 6f 6b 65 6e 50 72 69 76 69 6c 65 67 65 73 } //1 AdjustTokenPrivileges
		$a_01_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}