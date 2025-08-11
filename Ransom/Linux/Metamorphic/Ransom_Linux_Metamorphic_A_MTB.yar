
rule Ransom_Linux_Metamorphic_A_MTB{
	meta:
		description = "Ransom:Linux/Metamorphic.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 65 74 61 6d 6f 72 70 68 69 63 5f 6d 61 6c 77 61 72 65 5f 67 65 6e 65 72 61 74 6f 72 } //1 metamorphic_malware_generator
		$a_01_1 = {6d 61 6c 77 61 72 65 5f 32 5f 6d 65 74 61 6d 6f 72 70 68 69 63 } //1 malware_2_metamorphic
		$a_01_2 = {6d 61 6c 77 61 72 65 5f 32 5f 70 72 6f 63 65 73 73 65 64 5f 73 6f 75 72 63 65 } //1 malware_2_processed_source
		$a_01_3 = {52 61 6e 64 6f 6d 77 61 72 65 20 62 79 20 5b 61 66 6a 6f 73 65 70 68 5d } //1 Randomware by [afjoseph]
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}