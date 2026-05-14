
rule Trojan_Win64_LummaStealer_LM_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,37 00 37 00 06 00 00 "
		
	strings :
		$a_81_0 = {55 70 64 61 74 65 46 75 6e 63 74 69 6f 6e 50 61 72 61 6d 39 39 } //20 UpdateFunctionParam99
		$a_81_1 = {49 6e 69 74 50 72 6f 63 65 73 73 36 38 } //15 InitProcess68
		$a_81_2 = {57 72 69 74 65 48 65 61 70 36 39 } //10 WriteHeap69
		$a_81_3 = {41 64 64 48 65 61 70 38 33 } //5 AddHeap83
		$a_81_4 = {44 69 73 61 62 6c 65 46 69 6c 65 53 74 61 74 65 36 30 } //3 DisableFileState60
		$a_81_5 = {44 6c 6c 49 6d 70 6f 72 74 43 6f 6e 74 65 78 74 33 38 } //2 DllImportContext38
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*15+(#a_81_2  & 1)*10+(#a_81_3  & 1)*5+(#a_81_4  & 1)*3+(#a_81_5  & 1)*2) >=55
 
}