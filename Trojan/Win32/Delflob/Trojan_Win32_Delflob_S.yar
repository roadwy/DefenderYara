
rule Trojan_Win32_Delflob_S{
	meta:
		description = "Trojan:Win32/Delflob.S,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {4c 69 73 74 56 69 65 77 4d 61 6c 77 61 72 65 73 6c } //2 ListViewMalwaresl
		$a_01_1 = {61 63 74 5f 53 74 61 72 74 53 63 61 6e } //2 act_StartScan
		$a_01_2 = {61 63 74 5f 50 61 75 73 65 53 63 61 6e } //2 act_PauseScan
		$a_01_3 = {63 62 53 63 61 6e 4f 6e 53 74 61 72 74 75 70 } //2 cbScanOnStartup
		$a_01_4 = {4c 69 73 74 56 69 65 77 4d 61 6c 77 61 72 65 73 43 75 73 74 6f 6d 44 72 61 77 49 74 65 6d } //2 ListViewMalwaresCustomDrawItem
		$a_01_5 = {2f 69 6e 64 65 78 2e 70 68 70 3f 6c 61 3d 6f 72 64 65 72 23 31 } //2 /index.php?la=order#1
		$a_01_6 = {68 61 73 20 66 6f 75 6e 64 20 25 64 20 75 73 65 6c 65 73 73 20 20 61 6e 64 20 55 4e 57 41 4e 54 45 44 20 66 69 6c 65 73 20 6f 6e 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 21 } //1 has found %d useless  and UNWANTED files on your computer!
		$a_01_7 = {63 72 69 74 69 63 61 6c 20 70 72 69 76 61 63 79 20 63 6f 6d 72 6f 6d 69 73 69 6e 67 20 63 6f 6e 74 65 6e 74 } //1 critical privacy comromising content
		$a_01_8 = {6d 65 64 69 75 6d 20 70 72 69 76 61 63 79 20 74 68 72 65 61 74 73 } //1 medium privacy threats
		$a_01_9 = {74 6f 20 62 65 20 6a 75 6e 6b 20 63 6f 6e 74 65 6e 74 20 6f 66 20 6c 6f 77 20 70 72 69 76 61 63 79 20 74 68 72 65 61 74 73 } //1 to be junk content of low privacy threats
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}