
rule Trojan_BAT_Bsymem_AAMO_MTB{
	meta:
		description = "Trojan:BAT/Bsymem.AAMO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 0b 06 07 16 1a 6f 90 01 01 00 00 0a 26 07 16 28 90 01 01 00 00 0a 0c 06 16 73 90 01 01 00 00 0a 0d 08 8d 90 01 01 00 00 01 13 04 09 11 04 16 08 6f 90 01 01 00 00 0a 26 11 04 28 90 01 01 00 00 2b 28 90 01 01 00 00 2b 28 90 01 01 00 00 0a 13 05 11 05 90 00 } //4
		$a_01_1 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}