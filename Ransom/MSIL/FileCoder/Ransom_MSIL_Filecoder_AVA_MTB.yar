
rule Ransom_MSIL_Filecoder_AVA_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.AVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 2b 16 07 08 9a 28 90 01 03 06 2c 08 07 08 9a 28 90 01 03 0a 08 17 58 0c 08 07 8e 69 32 e4 90 00 } //01 00 
		$a_01_1 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //01 00  GetFolderPath
		$a_01_2 = {2e 00 6c 00 6f 00 63 00 6b 00 65 00 64 00 } //00 00  .locked
	condition:
		any of ($a_*)
 
}