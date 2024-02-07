
rule Backdoor_Win32_EGroupInstantAccess{
	meta:
		description = "Backdoor:Win32/EGroupInstantAccess,SIGNATURE_TYPE_PEHSTR,07 00 07 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 5c 43 6f 6e 6e 65 63 74 69 6f 6e 73 } //02 00  Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections
		$a_01_1 = {49 6e 74 65 72 6e 65 74 53 65 74 4f 70 74 69 6f 6e 20 66 61 69 6c 65 64 21 } //02 00  InternetSetOption failed!
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 65 67 72 6f 75 70 00 } //01 00  潓瑦慷敲敜牧畯p
		$a_01_3 = {20 3d 20 73 20 27 44 69 61 6c 43 6f 6d 20 43 6c 61 73 73 27 } //01 00   = s 'DialCom Class'
		$a_01_4 = {3d 20 73 20 27 49 45 44 69 61 6c 20 43 6c 61 73 73 27 } //00 00  = s 'IEDial Class'
	condition:
		any of ($a_*)
 
}