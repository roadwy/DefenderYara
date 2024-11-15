
rule Trojan_BAT_AsyncRAT_KAW_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.KAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1a 5d 16 fe 01 13 05 11 05 2c 12 08 07 11 04 91 1f 5b 61 b4 6f ?? 00 00 0a 00 00 2b 0d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}