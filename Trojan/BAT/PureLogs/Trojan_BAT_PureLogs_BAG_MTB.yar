
rule Trojan_BAT_PureLogs_BAG_MTB{
	meta:
		description = "Trojan:BAT/PureLogs.BAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 07 06 07 93 03 61 d1 9d 06 07 06 07 93 03 07 58 61 d1 9d 07 17 58 0b 07 06 8e 69 32 e2 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}