
rule Trojan_Win32_CryptInject_KL{
	meta:
		description = "Trojan:Win32/CryptInject.KL,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 3a 5c 77 6f 72 6b 73 70 61 63 65 5c 77 6f 72 6b 73 70 61 63 65 5f 63 5c 46 70 48 47 67 38 4a 6f 33 68 34 36 5f 31 32 5c 52 65 6c 65 61 73 65 5c 46 70 48 47 67 38 4a 6f 33 68 34 36 5f 31 32 2e 70 64 62 } //01 00  D:\workspace\workspace_c\FpHGg8Jo3h46_12\Release\FpHGg8Jo3h46_12.pdb
		$a_01_1 = {67 66 65 68 69 37 2e 32 69 68 73 66 61 } //01 00  gfehi7.2ihsfa
		$a_01_2 = {45 64 67 65 43 6f 6f 6b 69 65 73 56 69 65 77 5c 52 65 6c 65 61 73 65 5c 45 64 67 65 43 6f 6f 6b 69 65 73 56 69 65 77 2e 70 64 62 } //01 00  EdgeCookiesView\Release\EdgeCookiesView.pdb
		$a_01_3 = {72 65 70 6f 72 74 73 2e 61 64 65 78 70 65 72 74 73 6d 65 64 69 61 } //01 00  reports.adexpertsmedia
		$a_01_4 = {6a 66 69 61 67 5f 67 67 2e 65 78 65 } //01 00  jfiag_gg.exe
		$a_01_5 = {66 6a 67 68 61 32 33 5f 66 61 2e 74 78 74 } //00 00  fjgha23_fa.txt
		$a_01_6 = {00 5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}