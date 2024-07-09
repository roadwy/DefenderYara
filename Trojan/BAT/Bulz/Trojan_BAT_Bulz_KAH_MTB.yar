
rule Trojan_BAT_Bulz_KAH_MTB{
	meta:
		description = "Trojan:BAT/Bulz.KAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 08 9a 14 17 8d ?? 00 00 01 0d 09 16 02 8c ?? 00 00 01 a2 09 6f ?? 00 00 0a 74 ?? 00 00 1b 0b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}