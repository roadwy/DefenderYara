
rule Trojan_BAT_BitRAT_FAT_MTB{
	meta:
		description = "Trojan:BAT/BitRAT.FAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 08 02 8e 69 5d 7e ?? 00 00 04 02 08 02 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? 00 00 06 02 08 1e 58 1d 59 02 8e 69 5d 91 59 20 ?? 00 00 00 58 18 58 20 00 01 00 00 5d d2 9c 08 17 58 16 2c 3f 26 08 6a 02 8e 69 15 2c fc 17 59 6a 06 17 58 16 2d fb } //5
		$a_03_1 = {03 08 03 8e 69 5d 7e ?? 00 00 04 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? 00 00 06 03 08 1e 58 1d 59 03 8e 69 5d 91 59 20 ?? 00 00 00 58 18 58 20 00 01 00 00 5d d2 9c 08 17 58 16 2c 3f 26 08 6a 03 8e 69 15 2c fc 17 59 6a 06 17 58 16 2d fb } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=5
 
}