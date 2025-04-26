
rule Ransom_MSIL_HiddenTear_RDB_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTear.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {5d 6f 1e 00 00 0a 61 d2 9c 08 17 58 0c 08 06 8e 69 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}