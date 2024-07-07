
rule Trojan_Win32_Baiso_B{
	meta:
		description = "Trojan:Win32/Baiso.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {77 69 6e 61 6d 70 69 2e 65 78 65 00 75 70 64 61 74 65 72 65 61 6c } //1
		$a_01_1 = {5c 64 6c 6c 68 6f 73 74 73 2e 64 6c 6c 00 00 00 6d 73 6e 6e 74 } //1
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 49 4e 44 4f 57 53 5c 43 55 52 52 45 4e 54 56 45 52 53 49 4f 4e 5c 52 55 4e } //1 SOFTWARE\Microsoft\WINDOWS\CURRENTVERSION\RUN
		$a_01_3 = {00 5c 7b 70 63 68 6f 6d 65 7d 5c 00 00 2e 73 65 74 75 70 00 00 62 61 69 73 6f 00 00 00 6d 63 71 00 5c 6c 69 62 } //1
		$a_00_4 = {57 69 6e 45 78 65 63 } //1 WinExec
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}