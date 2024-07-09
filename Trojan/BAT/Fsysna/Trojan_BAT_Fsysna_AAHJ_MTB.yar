
rule Trojan_BAT_Fsysna_AAHJ_MTB{
	meta:
		description = "Trojan:BAT/Fsysna.AAHJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 0b 08 16 8c ?? 00 00 01 07 6f ?? 00 00 0a 17 da 8c ?? 00 00 01 17 8c ?? 00 00 01 12 03 12 02 28 ?? 00 00 0a 39 ?? 00 00 00 06 07 08 28 ?? 00 00 0a 16 6f ?? 00 00 0a 13 04 12 04 28 ?? 00 00 0a 6f ?? 00 00 0a 08 09 12 02 28 ?? 00 00 0a 2d d9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}