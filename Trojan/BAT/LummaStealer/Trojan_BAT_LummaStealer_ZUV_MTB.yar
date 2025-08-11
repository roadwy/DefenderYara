
rule Trojan_BAT_LummaStealer_ZUV_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.ZUV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 11 05 11 07 6f ?? 00 00 0a 13 08 12 08 28 ?? 00 00 0a 12 08 28 ?? 00 00 0a 58 86 12 08 28 ?? 00 00 0a 58 86 6c 23 00 00 00 00 00 00 08 40 5b 28 ?? 00 00 0a b7 13 09 11 09 04 d8 20 ff 00 00 00 5b 13 0a 09 11 05 11 07 11 0a 11 0a 11 0a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}