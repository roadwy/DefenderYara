
rule TrojanSpy_Linux_SeaSpy_A_MTB{
	meta:
		description = "TrojanSpy:Linux/SeaSpy.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 2f 42 61 72 72 61 63 75 64 61 4d 61 69 6c 53 65 72 76 69 63 65 20 3c 4e 65 74 77 6f 72 6b 2d 49 6e 74 65 72 66 61 63 65 3e } //01 00 
		$a_01_1 = {70 63 61 70 5f 6c 6f 6f 6b 75 70 6e 65 74 } //01 00 
		$a_01_2 = {65 6e 74 65 72 20 6f 70 65 6e 20 74 74 79 20 73 68 65 6c 6c } //01 00 
		$a_01_3 = {4e 4f 20 70 6f 72 74 20 63 6f 64 65 } //00 00 
	condition:
		any of ($a_*)
 
}