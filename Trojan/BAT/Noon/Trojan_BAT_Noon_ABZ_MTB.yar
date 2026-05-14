
rule Trojan_BAT_Noon_ABZ_MTB{
	meta:
		description = "Trojan:BAT/Noon.ABZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 11 04 5d 13 10 06 11 04 5b 13 11 09 11 10 11 11 6f ?? 01 00 0a 13 16 11 06 11 05 12 16 28 ?? 01 00 0a 9c 11 05 17 58 13 05 06 17 58 0a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}