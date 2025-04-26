
rule Trojan_Win32_Vundo{
	meta:
		description = "Trojan:Win32/Vundo,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 40 42 0f 00 6a 00 ff 15 } //1
		$a_01_1 = {68 00 14 01 00 68 c8 43 40 00 50 } //1
		$a_00_2 = {c1 ea 0b 83 e2 03 8b c3 c1 e8 05 8b cb c1 e1 04 33 c1 8b 4c 95 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}
rule Trojan_Win32_Vundo_2{
	meta:
		description = "Trojan:Win32/Vundo,SIGNATURE_TYPE_PEHSTR_EXT,34 00 34 00 0b 00 00 "
		
	strings :
		$a_00_0 = {25 30 38 78 5f 5f 5f 31 32 } //10 %08x___12
		$a_00_1 = {50 65 6e 64 69 6e 67 46 69 6c 65 52 65 6e 61 6d 65 4f 70 65 72 61 74 69 6f 6e } //10 PendingFileRenameOperation
		$a_00_2 = {3c 72 65 64 69 72 65 63 74 3e 3c } //10 <redirect><
		$a_01_3 = {41 4e 54 49 53 50 59 57 41 52 45 3f 47 43 41 53 53 45 52 56 41 4c 45 52 54 2e 45 58 45 } //10 ANTISPYWARE?GCASSERVALERT.EXE
		$a_00_4 = {50 6f 70 75 70 73 53 68 6f 77 6e 3d 25 69 3b 4d 61 78 50 6f 70 75 70 50 65 72 44 61 79 } //10 PopupsShown=%i;MaxPopupPerDay
		$a_00_5 = {67 5f 41 66 66 69 6c 69 61 74 65 49 44 } //1 g_AffiliateID
		$a_00_6 = {4c 6f 63 61 6c 5c 53 79 73 55 70 64 } //1 Local\SysUpd
		$a_00_7 = {41 20 6c 6f 74 20 6f 66 20 63 72 61 73 68 65 73 } //1 A lot of crashes
		$a_00_8 = {73 72 63 3d 22 68 74 74 70 3a 2f 2f 73 74 61 74 2e 65 72 72 63 6c 65 61 6e } //1 src="http://stat.errclean
		$a_00_9 = {63 61 6d 70 61 69 67 6e 73 65 6c 65 63 74 69 6f 6e } //1 campaignselection
		$a_00_10 = {73 79 73 70 72 6f 74 65 63 74 2e 63 6f 6d } //1 sysprotect.com
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_01_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1) >=52
 
}