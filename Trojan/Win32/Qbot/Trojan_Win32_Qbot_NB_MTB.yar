
rule Trojan_Win32_Qbot_NB_MTB{
	meta:
		description = "Trojan:Win32/Qbot.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_00_0 = {33 55 f0 89 55 f0 8b 45 ec 8b 4d f8 d3 f8 83 f0 04 89 45 ec 8b 55 f4 03 55 08 8b 4d 08 d3 e2 8b 4d 08 d3 fa 8b 4d f8 d3 fa 8b 4d f8 d3 e2 8b 4d 08 d3 } //10
		$a_81_1 = {72 6f 6c 6c 69 63 68 65 } //3 rolliche
		$a_81_2 = {74 72 69 6f 62 6f 6c } //3 triobol
		$a_81_3 = {44 6c 6c 5c 6f 75 74 2e 70 64 62 } //3 Dll\out.pdb
	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3) >=19
 
}
rule Trojan_Win32_Qbot_NB_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b7 f2 8d [0-03] 89 [0-05] 8d [0-02] bf [0-04] 2b fe 03 d7 0f [0-06] 03 [0-05] 8b [0-03] 89 [0-05] 8b [0-05] 8d [0-06] 8b [0-02] 0f [0-02] 39 [0-05] 90 18 83 [0-04] 8a c2 b3 11 f6 eb 81 [0-05] 02 c1 81 [0-07] 89 [0-05] 89 [0-02] 0f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}