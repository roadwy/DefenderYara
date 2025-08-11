
rule Trojan_BAT_OrcusRAT_EABP_MTB{
	meta:
		description = "Trojan:BAT/OrcusRAT.EABP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 09 06 09 91 08 09 08 8e 69 5d 91 61 d2 9c 09 17 58 0d 09 06 8e 69 32 e7 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}