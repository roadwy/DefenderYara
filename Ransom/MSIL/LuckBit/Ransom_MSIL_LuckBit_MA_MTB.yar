
rule Ransom_MSIL_LuckBit_MA_MTB{
	meta:
		description = "Ransom:MSIL/LuckBit.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {06 6f 47 00 00 0a 1e 5b 1f 0b 59 8d 90 01 01 00 00 01 0d 2b 1b 06 09 28 90 01 03 0a 6f 90 01 03 0a 13 04 08 11 04 16 11 04 8e 69 6f 90 01 03 0a 07 09 16 09 8e 69 6f 90 01 03 0a 16 30 d7 de 1e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}