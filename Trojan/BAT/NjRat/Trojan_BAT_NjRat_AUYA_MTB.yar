
rule Trojan_BAT_NjRat_AUYA_MTB{
	meta:
		description = "Trojan:BAT/NjRat.AUYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 06 8f ?? 00 00 01 25 71 ?? 00 00 01 11 06 0e 04 58 20 ff 00 00 00 5f d2 61 d2 81 ?? 00 00 01 1f 0d 13 0e 38 } //5
		$a_01_1 = {11 05 11 08 09 06 11 08 58 93 11 06 11 08 07 58 11 07 5d 93 61 d1 9d 17 11 08 58 13 08 00 11 08 08 fe 04 2d da } //2
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}