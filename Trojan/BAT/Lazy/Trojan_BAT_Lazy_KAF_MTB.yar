
rule Trojan_BAT_Lazy_KAF_MTB{
	meta:
		description = "Trojan:BAT/Lazy.KAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 08 9a 6f 90 01 01 00 00 0a 17 8d 90 01 01 00 00 01 25 16 1f 7c 9d 6f 90 01 01 00 00 0a 0d 09 8e 69 18 33 2e 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}