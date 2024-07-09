
rule Trojan_BAT_Lazy_PSVR_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PSVR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 37 00 00 0a 28 ?? 00 00 06 28 ?? 00 00 06 72 d6 01 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 0c 08 2c 5f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}