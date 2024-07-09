
rule Trojan_BAT_NanoCore_FAT_MTB{
	meta:
		description = "Trojan:BAT/NanoCore.FAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 04 17 58 0c 02 11 04 09 28 ?? 00 00 06 02 11 04 09 28 ?? 00 00 06 91 06 11 04 06 8e 69 28 ?? 00 00 06 91 61 02 08 09 28 ?? 00 00 06 91 28 ?? 00 00 06 07 58 07 5d d2 9c 11 04 15 58 13 04 11 04 16 2f bc } //3
		$a_01_1 = {4e 00 6f 00 59 00 6f 00 75 00 } //2 NoYou
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}