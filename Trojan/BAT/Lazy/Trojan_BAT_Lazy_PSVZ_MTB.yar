
rule Trojan_BAT_Lazy_PSVZ_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PSVZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 05 12 05 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 28 90 01 01 00 00 06 28 90 01 01 00 00 06 3a b0 ff ff ff 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}