
rule Trojan_BAT_GurcuStealer_A_MTB{
	meta:
		description = "Trojan:BAT/GurcuStealer.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 01 00 fe 09 00 00 fe 0c 90 01 01 00 6f 90 01 01 00 00 0a fe 0c 00 00 fe 0c 90 01 01 00 fe 0c 00 00 6f 90 01 01 00 00 0a 5d 6f 90 01 01 00 00 0a 61 d1 fe 0e 90 01 01 00 fe 0d 90 01 01 00 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a fe 0e 01 00 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}