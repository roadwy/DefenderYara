
rule Ransom_MSIL_WPlague_DA_MTB{
	meta:
		description = "Ransom:MSIL/WPlague.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {59 4f 55 52 20 46 49 4c 45 53 20 47 4f 54 20 45 4e 43 52 50 54 45 44 } //1 YOUR FILES GOT ENCRPTED
		$a_81_1 = {52 61 6e 73 6f 6d 77 61 72 65 32 2e 30 } //1 Ransomware2.0
		$a_81_2 = {52 61 73 6f 6d 77 61 72 65 32 2e 5f 30 2e 52 61 6e 73 6f 6d 77 61 72 65 32 2e 72 65 73 6f 75 72 63 65 73 } //1 Rasomware2._0.Ransomware2.resources
		$a_81_3 = {57 61 6e 6e 61 50 6c 61 67 75 45 2e 65 78 65 } //1 WannaPlaguE.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}