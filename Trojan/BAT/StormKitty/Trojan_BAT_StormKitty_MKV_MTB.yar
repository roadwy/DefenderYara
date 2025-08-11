
rule Trojan_BAT_StormKitty_MKV_MTB{
	meta:
		description = "Trojan:BAT/StormKitty.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 e6 02 06 28 ?? 01 00 0a 0b 07 7e b0 02 00 04 32 02 14 2a 06 1a 58 0a 07 8d ac 00 00 01 0c 02 06 08 16 07 28 ?? 01 00 0a 06 07 58 0a 02 06 28 ?? 01 00 0a 0d 09 7e b0 02 00 04 32 02 14 2a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}