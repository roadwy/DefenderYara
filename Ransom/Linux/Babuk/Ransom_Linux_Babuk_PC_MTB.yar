
rule Ransom_Linux_Babuk_PC_MTB{
	meta:
		description = "Ransom:Linux/Babuk.PC!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2e 64 69 73 6b 68 65 6c 70 79 6f 75 } //1 .diskhelpyou
		$a_01_1 = {2f 48 6f 77 20 54 6f 20 52 65 73 74 6f 72 65 20 59 6f 75 72 20 46 69 6c 65 73 2e 74 78 74 } //1 /How To Restore Your Files.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}