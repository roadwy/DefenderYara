
rule Worm_Win32_Wogue_C{
	meta:
		description = "Worm:Win32/Wogue.C,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 07 00 00 "
		
	strings :
		$a_02_0 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d [0-08] 2e 70 69 66 } //10
		$a_00_1 = {3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //10 :\autorun.inf
		$a_02_2 = {44 69 72 65 63 74 58 [0-02] 2e 64 6c 6c } //5
		$a_00_3 = {4e 65 74 20 53 74 6f 70 20 4e 6f 72 74 6f 6e 20 41 6e 74 69 76 69 72 75 73 20 41 75 74 6f 20 50 72 6f 74 65 63 74 20 53 65 72 76 69 63 65 } //1 Net Stop Norton Antivirus Auto Protect Service
		$a_00_4 = {4e 65 74 20 53 74 6f 70 20 6d 63 73 68 69 65 6c 64 } //1 Net Stop mcshield
		$a_00_5 = {6e 65 74 20 73 74 6f 70 20 22 57 69 6e 64 6f 77 73 20 46 69 72 65 77 61 6c 6c 2f 49 6e 74 65 72 6e 65 74 20 43 6f 6e 6e 65 63 74 69 6f 6e 20 53 68 61 72 69 6e 67 20 28 49 43 53 29 22 } //1 net stop "Windows Firewall/Internet Connection Sharing (ICS)"
		$a_00_6 = {6e 65 74 20 73 74 6f 70 20 53 79 73 74 65 6d 20 52 65 73 74 6f 72 65 20 53 65 72 76 69 63 65 } //1 net stop System Restore Service
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_02_2  & 1)*5+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=26
 
}