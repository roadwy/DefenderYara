
rule Trojan_Win64_RustyStealer_MMR_MTB{
	meta:
		description = "Trojan:Win64/RustyStealer.MMR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 2f 43 39 36 2e 39 2e 31 32 35 2e 32 30 30 } //1 cmd/C96.9.125.200
		$a_01_1 = {55 73 65 72 73 5c 50 75 62 6c 69 63 5c 4c 69 62 72 61 72 69 65 73 5c 73 79 73 74 65 6d 68 65 6c 70 65 72 2e 65 78 65 } //1 Users\Public\Libraries\systemhelper.exe
		$a_01_2 = {72 65 76 73 68 65 6c 6c 2e 70 64 62 } //1 revshell.pdb
		$a_01_3 = {52 75 73 74 42 61 63 6b 74 72 61 63 65 4d 75 74 65 78 } //1 RustBacktraceMutex
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}