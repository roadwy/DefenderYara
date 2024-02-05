
rule Ransom_Java_Filecoder_B_MTB{
	meta:
		description = "Ransom:Java/Filecoder.B!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {74 72 79 65 6e 63 72 70 74 } //01 00 
		$a_00_1 = {5c 72 65 61 64 6d 65 6f 6e 6e 6f 74 65 70 61 64 2e 6a 61 76 61 65 6e 63 72 79 70 74 } //01 00 
		$a_00_2 = {44 45 53 6b 65 79 2e 64 61 74 } //00 00 
	condition:
		any of ($a_*)
 
}