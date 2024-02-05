
rule Ransom_MSIL_Filecoder_PAY_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.PAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {09 11 04 91 25 07 61 13 05 02 58 20 90 01 03 00 5d 0b 06 08 25 17 58 0c 11 05 d2 9c 11 04 17 58 13 04 11 04 09 8e 69 32 d7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}