
rule Ransom_Linux_Filecoder_R_MTB{
	meta:
		description = "Ransom:Linux/Filecoder.R!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 8b 95 b8 fe ff ff 8b 85 98 fe ff ff 48 98 0f b6 04 02 89 c1 8b 85 84 fe ff ff 48 63 d0 48 69 d2 67 66 66 66 48 c1 ea 20 c1 fa 02 c1 f8 1f 29 c2 89 d0 01 c8 89 c1 48 8b 95 b8 fe ff ff 8b 85 98 fe ff ff 48 98 88 0c 02 83 85 98 fe ff ff 01 8b 85 98 fe ff ff 3b 85 9c fe ff ff } //01 00 
		$a_01_1 = {65 6e 63 72 79 70 74 44 69 72 } //00 00  encryptDir
	condition:
		any of ($a_*)
 
}