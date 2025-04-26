
rule Trojan_Win64_Rozena_DA_MTB{
	meta:
		description = "Trojan:Win64/Rozena.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_81_0 = {4d 65 6d 6f 72 79 20 64 75 6d 70 20 63 6f 6d 70 6c 65 74 65 64 } //1 Memory dump completed
		$a_81_1 = {44 65 63 6f 79 20 70 61 63 6b 65 74 20 73 65 6e 74 } //10 Decoy packet sent
		$a_81_2 = {4d 69 6e 69 44 75 6d 70 57 72 69 74 65 44 75 6d 70 } //1 MiniDumpWriteDump
		$a_81_3 = {25 73 5c 64 75 6d 70 66 69 6c 65 5f 25 75 2e 64 6d 70 } //1 %s\dumpfile_%u.dmp
		$a_81_4 = {45 6e 74 65 72 20 72 65 63 65 69 76 65 72 20 49 50 3a } //1 Enter receiver IP:
		$a_81_5 = {45 6e 74 65 72 20 72 65 63 65 69 76 65 72 20 70 6f 72 74 3a } //1 Enter receiver port:
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*10+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=15
 
}