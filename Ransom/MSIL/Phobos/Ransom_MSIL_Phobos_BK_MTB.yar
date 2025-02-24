
rule Ransom_MSIL_Phobos_BK_MTB{
	meta:
		description = "Ransom:MSIL/Phobos.BK!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 08 1b 58 1a 59 02 8e 69 5d 91 59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58 0c 08 6a 02 8e 69 17 59 6a 06 17 58 6e 5a 31 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}