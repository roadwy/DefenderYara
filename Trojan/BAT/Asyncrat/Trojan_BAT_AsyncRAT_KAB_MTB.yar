
rule Trojan_BAT_AsyncRAT_KAB_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.KAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 00 11 02 11 00 11 02 93 20 ?? 00 00 00 61 02 61 d1 9d } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}