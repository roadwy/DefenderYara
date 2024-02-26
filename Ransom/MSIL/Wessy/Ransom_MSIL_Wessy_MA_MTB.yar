
rule Ransom_MSIL_Wessy_MA_MTB{
	meta:
		description = "Ransom:MSIL/Wessy.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 1f 10 8d 90 01 03 01 25 d0 74 00 00 04 28 90 01 03 0a 6f 90 01 03 0a 06 07 6f 90 01 03 0a 17 73 21 00 00 0a 25 02 16 02 8e 69 6f 90 01 03 0a 6f 90 01 03 0a 06 28 90 01 03 06 28 90 01 03 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}