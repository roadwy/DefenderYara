
rule Spammer_Win32_EmailBomb_H{
	meta:
		description = "Spammer:Win32/EmailBomb.H,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {68 74 74 70 3a 2f 2f 70 72 6f 74 65 63 74 79 6f 75 72 70 63 2d 31 90 01 01 2e 63 6f 6d 2f 69 65 90 00 } //1
		$a_00_1 = {5c 4c 6f 77 52 65 67 69 73 74 72 79 5c 44 6f 6e 74 53 68 6f 77 4d 65 54 68 69 73 44 69 61 6c 6f 67 41 67 61 69 6e } //1 \LowRegistry\DontShowMeThisDialogAgain
		$a_00_2 = {25 73 3f 74 79 70 65 3d 25 73 26 73 79 73 74 65 6d 3d 25 73 26 69 64 3d 25 73 26 73 74 61 74 75 73 3d 25 73 26 6e 3d 25 64 26 65 78 74 72 61 3d 25 73 } //1 %s?type=%s&system=%s&id=%s&status=%s&n=%d&extra=%s
		$a_02_3 = {68 74 74 70 3a 2f 2f 70 72 6f 74 65 63 74 79 6f 75 72 70 63 2d 31 90 01 01 2e 63 6f 6d 2f 6f 75 74 32 2f 6d 73 6e 5f 69 6d 61 69 6c 65 72 5f 76 90 02 02 2e 74 78 74 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}