
rule Trojan_Linux_Flooder_B_MTB{
	meta:
		description = "Trojan:Linux/Flooder.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 59 4e 20 66 6c 6f 6f 64 65 72 20 74 68 72 65 61 64 } //01 00 
		$a_00_1 = {52 75 6e 20 61 20 64 2e 6f 2e 73 2e 20 61 74 74 61 63 6b 20 61 67 61 69 6e 73 74 20 61 6e 20 49 50 20 61 64 64 72 65 73 73 } //01 00 
		$a_00_2 = {70 6c 75 67 69 6e 5f 6c 6f 61 64 } //01 00 
		$a_00_3 = {70 6c 75 67 2d 69 6e 73 2f 64 6f 73 5f 61 74 74 61 63 6b 2f 64 6f 73 5f 61 74 74 61 63 6b 2e 63 } //00 00 
	condition:
		any of ($a_*)
 
}