
rule Trojan_BAT_Jalapeno_ZLG_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.ZLG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 1d 11 1e 6f ?? 00 00 0a 13 1f 11 12 03 fe 04 2c 14 11 0f 12 1f 28 ?? 00 00 0a 6f ?? 00 00 0a 11 12 17 58 13 12 11 12 03 fe 04 2c 14 11 0f 12 1f } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}