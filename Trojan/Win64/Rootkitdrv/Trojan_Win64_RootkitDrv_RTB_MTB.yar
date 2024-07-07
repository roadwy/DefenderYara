
rule Trojan_Win64_RootkitDrv_RTB_MTB{
	meta:
		description = "Trojan:Win64/RootkitDrv.RTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 08 00 00 "
		
	strings :
		$a_81_0 = {51 75 66 61 6e 50 61 63 52 65 67 52 75 6c 42 75 66 66 } //1 QufanPacRegRulBuff
		$a_81_1 = {5c 4d 69 72 42 74 5f 44 2e 70 64 62 } //10 \MirBt_D.pdb
		$a_81_2 = {5c 4d 69 72 42 74 5f 46 2e 70 64 62 } //10 \MirBt_F.pdb
		$a_81_3 = {5c 46 69 76 65 53 79 73 4d 69 72 42 74 5f 44 2e 70 64 62 } //10 \FiveSysMirBt_D.pdb
		$a_81_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_81_5 = {47 65 74 53 74 61 72 74 75 70 49 6e 66 6f 57 } //1 GetStartupInfoW
		$a_81_6 = {64 65 2d 43 6f 6e 76 65 72 74 5c 63 33 32 72 74 6f 6d 62 2e 63 70 70 } //1 de-Convert\c32rtomb.cpp
		$a_81_7 = {53 68 65 6c 6c 45 78 65 63 75 74 65 45 78 41 } //1 ShellExecuteExA
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*10+(#a_81_2  & 1)*10+(#a_81_3  & 1)*10+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=13
 
}