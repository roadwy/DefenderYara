
rule Trojan_Win32_Ditertag_A{
	meta:
		description = "Trojan:Win32/Ditertag.A,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {53 48 43 72 65 61 74 65 49 74 65 6d 46 72 6f 6d 50 61 72 73 69 6e 67 4e 61 6d 65 } //SHCreateItemFromParsingName  3
		$a_80_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 45 78 57 } //ShellExecuteExW  3
		$a_80_2 = {5c 73 79 73 70 72 65 70 5c 73 79 73 70 72 65 70 2e 65 78 65 } //\sysprep\sysprep.exe  3
		$a_80_3 = {45 6c 65 76 61 74 69 6f 6e 3a 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 21 } //Elevation:Administrator!  3
		$a_80_4 = {7b 33 61 64 30 35 35 37 35 2d 38 38 35 37 2d 34 38 35 30 2d 39 32 37 37 2d 31 31 62 38 35 62 64 62 38 65 30 39 7d } //{3ad05575-8857-4850-9277-11b85bdb8e09}  3
		$a_80_5 = {45 6e 61 62 6c 65 4c 55 41 } //EnableLUA  3
		$a_80_6 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 45 76 65 6e 74 2e 65 78 65 } //C:\Windows\SysEvent.exe  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}