
rule Worm_Win32_Autorun_XGB{
	meta:
		description = "Worm:Win32/Autorun.XGB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {52 45 43 59 43 4c 45 52 5c 61 75 74 6f 72 75 6e 65 2e 65 78 65 [0-20] 52 45 43 59 43 4c 45 52 [0-20] 61 75 74 6f 72 75 6e 2e 69 6e 66 [0-20] 5b 61 75 74 6f 72 75 6e 5d [0-20] 6f 70 65 6e 3d } //1
		$a_02_1 = {73 68 65 6c 6c 5c 6f 70 65 6e 3d 4f 70 65 6e [0-20] 73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d 52 45 43 59 43 4c 45 52 5c 61 75 74 6f 72 75 6e 65 2e 65 78 65 [0-20] 2d 4f 70 65 6e 43 75 72 44 69 72 } //1
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //1 SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}