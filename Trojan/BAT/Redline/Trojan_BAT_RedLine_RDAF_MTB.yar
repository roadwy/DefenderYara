
rule Trojan_BAT_RedLine_RDAF_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {6c 6b 64 6d 65 65 6b 61 6e 6b 64 49 6b } //1 lkdmeekankdIk
		$a_03_1 = {5d 91 61 28 90 01 04 02 06 1a 58 4a 1d 58 1c 59 02 8e 69 5d 91 59 20 fd 00 00 00 58 19 58 20 00 01 00 00 5d d2 9c 06 1a 58 06 1a 58 4a 17 58 54 90 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}