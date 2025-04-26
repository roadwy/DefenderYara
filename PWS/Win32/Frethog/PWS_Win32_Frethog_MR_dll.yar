
rule PWS_Win32_Frethog_MR_dll{
	meta:
		description = "PWS:Win32/Frethog.MR!dll,SIGNATURE_TYPE_PEHSTR_EXT,08 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {74 39 8b 4c 24 0c c6 00 60 2b c8 c6 40 01 54 83 e9 07 c6 40 02 e8 89 48 03 c6 40 07 61 c6 40 08 68 8b 56 01 50 56 8d 4c 32 05 c6 40 0d c3 } //5
		$a_03_1 = {2b c8 83 e9 05 6a 05 89 [0-0a] c6 [0-03] e9 } //2
		$a_01_2 = {8a 4c 24 18 8d 74 04 1c 8a 14 2e 32 d1 40 3b c7 88 16 72 ec } //2
		$a_01_3 = {47 6c 62 6b 76 6c 74 5f 65 76 74 5f 30 30 30 31 } //1 Glbkvlt_evt_0001
		$a_01_4 = {67 61 6d 65 5f 6c 6f 67 69 6e 66 6f 2e 6c 6f 67 } //1 game_loginfo.log
		$a_01_5 = {42 65 61 6e 50 61 73 73 } //1 BeanPass
		$a_01_6 = {59 41 48 4f 4f 4a 53 54 2b 48 4f 53 54 3a 25 73 2b 49 50 3a 25 73 2b 55 53 45 52 49 44 3a 25 73 2b 50 41 53 53 3a 25 73 2b 56 65 72 3a 25 73 } //1 YAHOOJST+HOST:%s+IP:%s+USERID:%s+PASS:%s+Ver:%s
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}