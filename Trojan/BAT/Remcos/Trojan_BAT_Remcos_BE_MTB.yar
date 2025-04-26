
rule Trojan_BAT_Remcos_BE_MTB{
	meta:
		description = "Trojan:BAT/Remcos.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {95 58 20 ff 00 00 00 5f 13 0e 11 05 13 0f 07 11 0f 91 13 10 11 04 11 0e 95 13 11 11 10 11 11 61 13 12 09 11 0f 11 12 d2 9c 11 05 17 58 13 05 00 11 05 6e 09 8e 69 6a fe 04 13 13 11 13 2d } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}