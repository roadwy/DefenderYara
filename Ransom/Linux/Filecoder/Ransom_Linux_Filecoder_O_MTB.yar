
rule Ransom_Linux_Filecoder_O_MTB{
	meta:
		description = "Ransom:Linux/Filecoder.O!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {48 89 85 f8 fb ff ff 8b 85 e8 fb ff ff 48 63 d0 48 8b 8d f8 fb ff ff 48 8d 85 10 fc ff ff be 01 00 00 00 48 89 c7 } //01 00 
		$a_01_1 = {65 6e 63 72 79 70 74 66 69 6c 65 } //00 00 
	condition:
		any of ($a_*)
 
}