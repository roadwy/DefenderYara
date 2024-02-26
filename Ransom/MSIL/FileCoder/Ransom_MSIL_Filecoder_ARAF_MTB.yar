
rule Ransom_MSIL_Filecoder_ARAF_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.ARAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {08 09 9a 13 04 00 11 04 6f 90 01 03 0a 6f 90 01 03 0a 72 81 01 00 70 28 90 01 03 0a 13 05 11 05 2c 3d 00 72 8b 01 00 70 13 06 11 04 6f 90 01 03 0a 11 04 6f 90 01 03 0a 72 9d 01 00 70 28 90 01 03 0a 11 06 28 90 01 03 06 00 11 04 6f 90 01 03 0a 28 90 01 03 0a 00 03 28 90 01 03 0a 00 00 00 09 17 58 0d 09 08 8e 69 32 96 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}