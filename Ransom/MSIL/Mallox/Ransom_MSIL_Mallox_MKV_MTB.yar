
rule Ransom_MSIL_Mallox_MKV_MTB{
	meta:
		description = "Ransom:MSIL/Mallox.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {25 2d 1f 26 7e 90 01 03 04 fe 90 01 03 00 06 73 90 01 03 0a 25 1d 2d 03 26 2b 07 80 90 01 03 04 2b 00 6f 90 01 03 06 de 03 26 de 00 d0 90 01 03 01 28 90 01 03 0a 28 90 01 03 06 74 90 01 03 01 72 90 01 03 70 28 90 01 03 0a 16 8d 90 01 03 01 6f 90 01 03 0a 74 90 01 03 01 2a 90 0a 65 00 7e 90 01 03 04 7e 90 01 03 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}