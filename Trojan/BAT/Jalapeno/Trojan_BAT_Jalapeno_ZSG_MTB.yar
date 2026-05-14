
rule Trojan_BAT_Jalapeno_ZSG_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.ZSG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 12 11 13 6f ?? 00 00 0a 13 14 11 0b 03 fe 04 2c 14 11 08 12 14 28 ?? 00 00 0a 6f ?? 00 00 0a 11 0b 17 58 13 0b 11 0b 03 fe 04 2c 14 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}