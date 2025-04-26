
rule Ransom_MSIL_Filecoder_SUX_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.SUX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 17 58 16 0b 45 1b 00 00 00 00 00 00 00 6a fe ff ff 73 fe ff ff 82 fe ff ff 91 fe ff ff a0 fe ff ff ad fe ff ff b3 fe ff ff c1 fe ff ff cb fe ff ff f5 fe ff ff da fe ff ff f3 fe ff ff f6 fe ff ff 29 ff ff ff f8 fe ff ff 0e ff ff ff 1d ff ff ff 28 ff ff ff 38 ff ff ff 43 ff ff ff 51 ff ff ff 5f ff ff ff 6d ff ff ff 78 ff ff ff 83 ff ff ff 85 ff ff ff de 3a 08 0b 06 1f fe 30 03 17 2b 01 06 45 02 00 00 00 00 00 00 00 70 ff ff ff de 20 75 27 00 00 01 14 fe 03 06 16 fe 03 5f 07 16 fe 01 5f fe 11 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}