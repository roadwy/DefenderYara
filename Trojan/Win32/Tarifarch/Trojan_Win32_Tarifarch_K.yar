
rule Trojan_Win32_Tarifarch_K{
	meta:
		description = "Trojan:Win32/Tarifarch.K,SIGNATURE_TYPE_PEHSTR,64 00 64 00 06 00 00 "
		
	strings :
		$a_01_0 = {37 37 27 23 1d 13 24 39 6e 6f 70 71 72 72 72 72 72 72 73 74 5e 67 75 5e 24 75 68 65 74 72 72 72 72 72 } //100 㜷⌧ጝ㤤潮煰牲牲牲瑳杞幵甤敨牴牲牲
		$a_01_1 = {6a 61 76 61 5f 75 70 64 2e 65 78 65 } //1 java_upd.exe
		$a_01_2 = {43 50 61 79 6d 65 6e 74 46 6f 72 6d } //1 CPaymentForm
		$a_01_3 = {52 65 6c 65 61 73 65 5c 61 72 63 5f 32 30 31 30 2e 70 64 62 } //1 Release\arc_2010.pdb
		$a_01_4 = {52 65 6c 65 61 73 65 5c 6e 65 77 5f 61 72 63 2e 70 64 62 } //1 Release\new_arc.pdb
		$a_01_5 = {52 65 6c 65 61 73 65 5c 61 72 63 5f 32 30 30 35 2e 70 64 62 } //1 Release\arc_2005.pdb
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=100
 
}