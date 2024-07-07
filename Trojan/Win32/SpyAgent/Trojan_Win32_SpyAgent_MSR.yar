
rule Trojan_Win32_SpyAgent_MSR{
	meta:
		description = "Trojan:Win32/SpyAgent!MSR,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 54 45 4d 50 5c 68 61 6c 65 6e 67 2e 65 78 65 } //1 C:\TEMP\haleng.exe
		$a_81_1 = {68 74 74 70 3a 2f 2f 75 65 68 67 65 34 67 36 47 68 2e 32 69 68 73 66 61 2e 63 6f 6d 2f 61 70 69 2f 3f 73 69 64 3d 30 26 6b 65 79 3d 38 65 35 36 62 65 63 64 39 65 64 39 39 65 64 66 35 37 64 34 31 65 31 64 64 37 33 31 31 38 63 35 } //1 http://uehge4g6Gh.2ihsfa.com/api/?sid=0&key=8e56becd9ed99edf57d41e1dd73118c5
		$a_81_2 = {44 3a 5c 77 6f 72 6b 73 70 61 63 65 5c 77 6f 72 6b 73 70 61 63 65 5f 63 5c 47 6a 37 65 55 39 33 6f 37 67 47 68 67 5f 31 39 5c 52 65 6c 65 61 73 65 5c 47 6a 37 65 55 39 33 6f 37 67 47 68 67 5f 31 39 2e 70 64 62 } //1 D:\workspace\workspace_c\Gj7eU93o7gGhg_19\Release\Gj7eU93o7gGhg_19.pdb
		$a_81_3 = {6a 66 69 61 67 33 67 5f 67 67 2e 65 78 65 } //1 jfiag3g_gg.exe
		$a_81_4 = {66 6a 34 67 68 67 61 32 33 5f 66 73 61 2e 74 78 74 } //1 fj4ghga23_fsa.txt
		$a_81_5 = {44 45 4c 45 54 45 20 46 52 4f 4d 20 63 6f 6f 6b 69 65 } //1 DELETE FROM cookie
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}