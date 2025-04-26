
rule Trojan_Win64_LummaStealer_VVG_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.VVG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 09 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 4d 64 35 45 6e 63 6f 64 65 } //1 main.Md5Encode
		$a_01_1 = {6d 61 69 6e 2e 52 44 46 } //1 main.RDF
		$a_01_2 = {6d 61 69 6e 2e 72 61 6e 64 53 65 71 } //1 main.randSeq
		$a_01_3 = {6d 61 69 6e 2e 4b 77 50 4d 48 7a 44 69 62 6c } //8 main.KwPMHzDibl
		$a_01_4 = {6d 61 69 6e 2e 5f 43 66 75 6e 63 5f 77 72 66 } //1 main._Cfunc_wrf
		$a_01_5 = {6d 61 69 6e 2e 54 65 72 6d 69 6e 61 74 65 50 72 6f 63 65 73 73 } //1 main.TerminateProcess
		$a_01_6 = {6d 61 69 6e 2e 43 72 65 61 74 65 53 75 73 70 65 6e 64 65 64 50 72 6f 63 65 73 73 } //1 main.CreateSuspendedProcess
		$a_01_7 = {6d 61 69 6e 2e 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 main.WriteProcessMemory
		$a_01_8 = {6d 61 69 6e 2e 5f 52 75 6e 50 45 } //1 main._RunPE
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*8+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=12
 
}