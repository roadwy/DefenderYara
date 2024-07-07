
rule Trojan_BAT_Strictor_KAA_MTB{
	meta:
		description = "Trojan:BAT/Strictor.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {69 5d 91 08 09 08 6f 90 01 01 01 00 0a 5d 6f 90 01 01 01 00 0a 61 28 90 01 01 01 00 0a 07 09 17 58 07 8e 69 5d 91 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}