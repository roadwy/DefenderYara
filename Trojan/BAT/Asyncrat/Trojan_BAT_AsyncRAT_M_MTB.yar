
rule Trojan_BAT_AsyncRAT_M_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 04 07 09 16 6f ?? 00 00 0a 25 26 13 04 12 04 28 ?? 00 00 0a 25 26 6f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}