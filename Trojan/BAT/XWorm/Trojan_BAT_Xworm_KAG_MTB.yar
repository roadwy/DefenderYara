
rule Trojan_BAT_Xworm_KAG_MTB{
	meta:
		description = "Trojan:BAT/Xworm.KAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {9a 0d 00 07 08 8f ?? 00 00 01 25 71 ?? 00 00 01 09 08 09 8e 69 5d 91 61 d2 81 ?? 00 00 01 00 11 07 17 58 13 07 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}