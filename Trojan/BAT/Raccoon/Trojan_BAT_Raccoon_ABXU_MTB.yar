
rule Trojan_BAT_Raccoon_ABXU_MTB{
	meta:
		description = "Trojan:BAT/Raccoon.ABXU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 1a 58 4a 02 8e 69 5d 7e 90 01 01 00 00 04 02 06 1a 58 4a 02 8e 69 5d 91 07 06 1a 58 4a 07 8e 69 5d 91 61 28 90 01 01 00 00 06 02 06 1a 58 4a 17 58 02 8e 69 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 06 1a 58 06 1a 58 4a 17 58 54 06 1a 58 4a 6a 02 8e 69 17 59 6a 06 4b 17 58 6e 5a 31 9c 0f 00 02 8e 69 17 59 28 90 01 01 00 00 2b 02 2a 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}