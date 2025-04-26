
rule Trojan_BAT_Injuke_AAPK_MTB{
	meta:
		description = "Trojan:BAT/Injuke.AAPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 72 df 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 73 ?? 00 00 0a 72 03 01 00 70 28 ?? 00 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 73 ?? 00 00 0a 72 19 01 00 70 28 ?? 00 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 73 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 0b de 0c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}