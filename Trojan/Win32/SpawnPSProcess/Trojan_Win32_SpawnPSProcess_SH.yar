
rule Trojan_Win32_SpawnPSProcess_SH{
	meta:
		description = "Trojan:Win32/SpawnPSProcess.SH,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 07 00 00 "
		
	strings :
		$a_80_0 = {20 26 20 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 77 69 6e 64 6f 77 73 74 79 6c 65 20 68 69 64 64 65 6e } // & powershell.exe -windowstyle hidden  1
		$a_80_1 = {20 26 20 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 77 20 31 } // & powershell.exe -w 1  1
		$a_80_2 = {20 26 20 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 77 20 68 } // & powershell.exe -w h  1
		$a_80_3 = {20 26 20 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 6e 6f 70 20 2d 77 20 68 69 64 64 65 6e } // & powershell.exe -nop -w hidden  1
		$a_80_4 = {20 62 79 70 61 73 73 20 } // bypass   5
		$a_80_5 = {2d 63 6f 6d 6d 61 6e 64 20 67 65 74 2d 70 72 6f 63 65 73 73 } //-command get-process  5
		$a_81_6 = {2d 65 6e 63 6f 64 65 64 63 6f 6d 6d 61 6e 64 20 5a 77 42 6c 41 48 51 41 4c 51 42 77 41 48 49 41 62 77 42 6a 41 47 55 41 63 77 42 7a 41 41 3d 3d 20 26 } //10 -encodedcommand ZwBlAHQALQBwAHIAbwBjAGUAcwBzAA== &
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*5+(#a_80_5  & 1)*5+(#a_81_6  & 1)*10) >=11
 
}