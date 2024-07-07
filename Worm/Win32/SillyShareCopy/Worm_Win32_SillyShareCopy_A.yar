
rule Worm_Win32_SillyShareCopy_A{
	meta:
		description = "Worm:Win32/SillyShareCopy.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {77 69 64 74 68 3d 30 20 68 65 69 67 68 74 3d 30 3e 3c 2f 49 66 72 41 6d 45 3e } //1 width=0 height=0></IfrAmE>
		$a_00_1 = {48 69 6a 61 63 6b 54 68 69 73 2e 65 78 65 } //1 HijackThis.exe
		$a_00_2 = {4b 41 56 33 32 2e 65 78 65 } //1 KAV32.exe
		$a_00_3 = {52 61 76 54 61 73 6b 2e 65 78 65 } //1 RavTask.exe
		$a_01_4 = {44 69 73 61 62 6c 65 52 65 67 69 73 74 72 79 54 6f 6f 6c 73 } //1 DisableRegistryTools
		$a_00_5 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 74 72 79 } //1 if exist "%s" goto try
		$a_00_6 = {44 69 73 61 62 6c 65 57 69 6e 64 6f 77 73 55 70 64 61 74 65 41 63 63 65 73 73 } //1 DisableWindowsUpdateAccess
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}