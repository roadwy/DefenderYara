
rule Trojan_Win32_Obfuse_PR_AMTB{
	meta:
		description = "Trojan:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {46 6f 72 6d 32 5f 4c 6f 61 64 } //1 Form2_Load
		$a_81_1 = {72 65 6d 6f 51 63 63 6f 75 6e 74 } //1 remoQccount
		$a_81_2 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_3 = {44 49 52 45 52 4e 49 46 } //1 DIRERNIF
		$a_81_4 = {67 65 74 5f 61 70 70 69 61 74 68 } //1 get_appiath
		$a_81_5 = {64 6f 77 6e 51 64 61 74 61 } //1 downQdata
		$a_81_6 = {6c 6f 61 64 51 64 61 74 61 } //1 loadQdata
		$a_81_7 = {24 34 34 61 61 30 65 38 64 2d 61 34 39 33 2d 34 37 33 63 2d 39 61 66 66 2d 66 35 61 38 32 31 39 64 66 66 35 66 } //1 $44aa0e8d-a493-473c-9aff-f5a8219dff5f
		$a_81_8 = {65 3a 5c 69 76 64 76 6d 72 73 20 76 69 64 6f 5c 69 76 64 76 6d 72 73 20 76 69 64 6f 5c 6f 62 6a 5c 44 65 62 75 67 5c 69 76 64 76 6d 72 73 20 76 69 64 6f 2e 70 64 62 } //1 e:\ivdvmrs vido\ivdvmrs vido\obj\Debug\ivdvmrs vido.pdb
		$a_81_9 = {53 4f 46 5f 54 57 41 5f 52 45 5c 4d 69 63 5f 72 6f 5f 73 6f 66 74 5c 57 69 6e 5f 64 6f 77 73 5c 43 75 72 5f 72 65 6e 74 5f 56 65 72 73 5f 69 6f 6e 5c 5f 52 75 6e } //1 SOF_TWA_RE\Mic_ro_soft\Win_dows\Cur_rent_Vers_ion\_Run
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}
rule Trojan_Win32_Obfuse_PR_AMTB_2{
	meta:
		description = "Trojan:Win32/Obfuse.PR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_81_0 = {44 49 52 53 4e 49 46 } //1 DIRSNIF
		$a_81_1 = {67 65 74 5f 61 70 70 69 61 74 68 } //1 get_appiath
		$a_81_2 = {46 6f 72 6d 31 5f 4c 6f 61 64 } //1 Form1_Load
		$a_81_3 = {72 65 6d 6f 51 63 63 6f 75 6e 74 } //1 remoQccount
		$a_81_4 = {64 6f 77 6e 51 64 61 74 61 } //1 downQdata
		$a_81_5 = {6c 6f 61 64 51 64 61 74 61 } //1 loadQdata
		$a_81_6 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_7 = {53 70 6c 69 74 } //1 Split
		$a_81_8 = {57 72 69 74 65 41 6c 6c 42 79 74 65 73 } //1 WriteAllBytes
		$a_81_9 = {24 30 36 38 39 34 36 63 62 2d 30 33 30 36 2d 34 37 63 64 2d 62 38 63 39 2d 39 35 63 38 37 39 64 34 66 31 34 33 } //1 $068946cb-0306-47cd-b8c9-95c879d4f143
		$a_81_10 = {65 3a 5c 77 71 65 65 78 5c 6a 65 64 76 6d 74 72 76 68 5c 6a 65 64 76 6d 74 72 76 68 5c 6f 62 6a 5c 44 65 62 75 67 5c 6a 65 64 76 6d 74 72 76 68 2e 70 64 62 } //1 e:\wqeex\jedvmtrvh\jedvmtrvh\obj\Debug\jedvmtrvh.pdb
		$a_81_11 = {53 4f 46 5f 54 57 41 5f 52 45 5c 4d 69 63 5f 72 6f 73 6f 66 74 5c 57 69 6e 5f 64 6f 77 73 5c 43 75 72 72 65 6e 74 5f 56 65 72 73 69 6f 6e 5c 5f 52 75 6e } //1 SOF_TWA_RE\Mic_rosoft\Win_dows\Current_Version\_Run
		$a_81_12 = {2e 65 78 65 7c } //1 .exe|
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1) >=13
 
}