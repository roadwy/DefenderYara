
rule Trojan_BAT_NjRAT_KAV_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.KAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 08 09 06 11 08 58 93 11 06 11 08 07 58 11 07 5d 93 61 d1 9d 1f 0e 13 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}