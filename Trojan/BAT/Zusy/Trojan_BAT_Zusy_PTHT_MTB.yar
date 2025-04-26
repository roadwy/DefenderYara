
rule Trojan_BAT_Zusy_PTHT_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PTHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 2c 28 06 28 ?? 00 00 0a 6f 15 00 00 0a 28 ?? 00 00 2b 6f 17 00 00 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}