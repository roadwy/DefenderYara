
rule Trojan_BAT_Tiny_ZKU_MTB{
	meta:
		description = "Trojan:BAT/Tiny.ZKU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 20 ff 00 00 00 33 53 07 6f ?? 00 00 0a 13 04 11 04 2d 0d 08 20 ff 00 00 00 6f ?? 00 00 0a 2b 42 1a 8d 39 00 00 01 13 05 11 05 16 11 04 d2 9c 07 11 05 17 19 6f ?? 00 00 0a 26 11 05 16 28 ?? 00 00 0a 13 06 11 06 8d 39 00 00 01 13 07 08 11 07 16 11 06 6f ?? 00 00 0a 2b 08 08 09 d2 6f ?? 00 00 0a 07 6f ?? 00 00 0a 25 0d 15 33 92 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}