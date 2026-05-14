
rule Ransom_Win64_Uragan_YBF_MTB{
	meta:
		description = "Ransom:Win64/Uragan.YBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //1 DisableTaskMgr
		$a_01_1 = {52 45 41 44 4d 45 2e 74 78 74 } //1 README.txt
		$a_01_2 = {47 6c 6f 62 61 6c 5c 55 72 61 67 61 6e 4d 75 74 65 78 } //1 Global\UraganMutex
		$a_01_3 = {6c 6f 63 6b 2e 70 6e 67 } //1 lock.png
		$a_01_4 = {65 6e 63 72 79 70 74 65 64 20 79 6f 75 72 20 69 6e 66 72 61 73 74 72 75 63 74 75 72 65 } //1 encrypted your infrastructure
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}