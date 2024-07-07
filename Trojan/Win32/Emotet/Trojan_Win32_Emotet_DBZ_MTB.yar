
rule Trojan_Win32_Emotet_DBZ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DBZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_00_0 = {01 d7 8b 75 e4 8a 3c 16 8b 55 ec 8b 75 b8 2a 1c 0e 00 fb 8b 4d ac 29 d1 8b 55 e0 8b 75 b0 88 1c 32 } //1
		$a_02_1 = {8b 45 e4 b9 90 01 04 8b 55 f4 8b 75 ec 8a 1c 06 29 d1 8b 55 e8 88 1c 02 01 c8 8b 4d f0 39 c8 89 45 e4 74 90 00 } //1
		$a_81_2 = {77 66 33 74 34 6a 61 73 32 76 33 39 76 32 33 } //1 wf3t4jas2v39v23
		$a_00_3 = {44 00 46 00 47 00 24 00 54 00 47 00 59 00 24 00 59 00 4e 00 } //1 DFG$TGY$YN
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_81_2  & 1)*1+(#a_00_3  & 1)*1) >=2
 
}