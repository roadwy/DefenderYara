
rule Ransom_Linux_Qilin_A_MTB{
	meta:
		description = "Ransom:Linux/Qilin.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {51 69 6c 69 6e } //1 Qilin
		$a_00_1 = {76 6d 73 76 63 2f 73 6e 61 70 73 68 6f 74 2e 72 65 6d 6f 76 65 61 6c 6c 20 25 6c 6c 75 } //1 vmsvc/snapshot.removeall %llu
		$a_00_2 = {5f 52 45 43 4f 56 45 52 2e 74 78 74 } //1 _RECOVER.txt
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}