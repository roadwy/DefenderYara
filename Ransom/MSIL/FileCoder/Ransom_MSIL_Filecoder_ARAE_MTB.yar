
rule Ransom_MSIL_Filecoder_ARAE_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.ARAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_80_0 = {41 6c 6c 20 6f 66 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //All of your files are encrypted  02 00 
		$a_80_1 = {54 6f 20 75 6e 6c 6f 63 6b 20 79 6f 75 72 20 66 69 6c 65 73 } //To unlock your files  02 00 
		$a_80_2 = {4a 75 73 74 20 73 65 6e 64 20 6d 65 20 3a } //Just send me :  02 00 
		$a_80_3 = {42 69 74 63 6f 69 6e } //Bitcoin  00 00 
	condition:
		any of ($a_*)
 
}