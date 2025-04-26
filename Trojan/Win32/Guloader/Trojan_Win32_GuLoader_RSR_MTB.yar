
rule Trojan_Win32_GuLoader_RSR_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RSR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {5c 6d 61 6a 6f 6c 69 63 61 73 5c 70 72 6f 74 6f 6e 65 6d 61 74 61 5c 6f 70 65 72 61 74 69 6f 6e 73 76 72 65 6c 73 65 72 } //1 \majolicas\protonemata\operationsvrelser
		$a_81_1 = {74 65 6c 65 76 61 65 72 6b 65 74 5c 73 6c 61 64 64 65 72 74 61 73 6b 65 72 2e 73 74 69 } //1 televaerket\sladdertasker.sti
		$a_81_2 = {69 6c 66 72 65 5c 69 6e 64 73 6b 75 64 73 5c } //1 ilfre\indskuds\
		$a_81_3 = {74 72 69 70 6f 64 20 65 6b 73 6b 6c 75 73 69 76 65 73 } //1 tripod eksklusives
		$a_81_4 = {62 6c 6f 6b 6b 72 79 70 74 6f 67 72 61 66 69 73 20 69 6e 64 73 65 6e 64 65 6c 73 65 72 6e 65 20 69 62 65 6e 68 6f 6c 74 73 66 6c 6a 74 65 73 } //1 blokkryptografis indsendelserne ibenholtsfljtes
		$a_81_5 = {61 6e 74 69 62 69 6f 74 69 6b 61 66 6f 72 62 72 75 67 65 74 2e 65 78 65 } //1 antibiotikaforbruget.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}