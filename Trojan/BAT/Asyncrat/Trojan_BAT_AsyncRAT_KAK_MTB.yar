
rule Trojan_BAT_AsyncRAT_KAK_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.KAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8e 69 5d 1f ?? 58 1f ?? 58 1f ?? 59 91 61 06 09 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}