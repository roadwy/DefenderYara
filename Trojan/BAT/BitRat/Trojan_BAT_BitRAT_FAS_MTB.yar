
rule Trojan_BAT_BitRAT_FAS_MTB{
	meta:
		description = "Trojan:BAT/BitRAT.FAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {58 4a 07 8e 69 5d 91 61 28 ?? 01 00 06 03 06 1a 58 4a 1d 58 1c 59 03 8e 69 5d 91 59 20 fd 00 00 00 58 19 58 20 00 01 00 00 5d d2 9c 06 1a 58 06 1a 58 4a 17 58 54 06 1a 58 4a 6a 03 8e 69 17 59 16 2d fb 6a 06 4b 17 58 6e 5a 31 95 18 2c e7 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}