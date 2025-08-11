
rule Ransom_Linux_Akira_E_MTB{
	meta:
		description = "Ransom:Linux/Akira.E!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 6b 69 72 61 6e 65 77 5f 52 6f 6f 74 20 70 61 74 68 } //1 akiranew_Root path
		$a_01_1 = {2f 69 6e 63 6c 75 64 65 2f 73 63 72 61 74 63 68 61 6b 69 72 61 6e 65 77 77 61 6c 6b 69 6e 67 } //1 /include/scratchakiranewwalking
		$a_01_2 = {61 6b 69 72 61 6e 65 77 2f 73 72 63 2f 6c 6f 63 6b 2e 72 73 23 3e 2d 20 46 69 6c 65 20 20 63 72 79 70 74 69 6e 67 2e 2e 2e 20 46 69 6c 65 20 6c 6f 63 6b 20 73 74 61 72 74 65 64 3a } //1 akiranew/src/lock.rs#>- File  crypting... File lock started:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}