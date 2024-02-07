
rule Ransom_MSIL_Filecoder_PAAV_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.PAAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {16 13 09 2b 1a 11 07 11 09 11 07 11 09 91 06 11 09 06 8e 69 5d 91 61 d2 9c 11 09 17 58 13 09 11 09 11 08 32 e0 } //01 00 
		$a_01_1 = {79 00 6f 00 75 00 72 00 20 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 20 00 68 00 61 00 73 00 20 00 62 00 65 00 65 00 6e 00 20 00 61 00 74 00 74 00 61 00 63 00 6b 00 65 00 64 00 20 00 62 00 79 00 20 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 } //00 00  your computer has been attacked by Ransomware
	condition:
		any of ($a_*)
 
}