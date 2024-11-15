
rule Trojan_Linux_Snapekit_A_MTB{
	meta:
		description = "Trojan:Linux/Snapekit.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 6e 61 70 65 6b 69 74 5f 43 32 } //1 snapekit_C2
		$a_01_1 = {73 6e 61 70 65 6b 69 74 5f 70 65 72 73 69 73 74 65 6e 63 65 } //1 snapekit_persistence
		$a_01_2 = {73 6e 61 70 65 6b 69 74 5f 66 69 6c 65 70 61 74 68 } //1 snapekit_filepath
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}