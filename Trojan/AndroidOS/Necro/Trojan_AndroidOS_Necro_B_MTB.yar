
rule Trojan_AndroidOS_Necro_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Necro.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6e 20 56 00 53 00 0a 06 12 f7 32 76 7b 00 71 20 b8 00 65 00 0c 06 21 27 21 68 b0 87 23 78 74 00 21 29 71 59 90 00 12 18 21 22 21 69 71 59 90 00 16 28 74 01 b6 00 12 00 0c 02 } //1
		$a_01_1 = {0c 01 6e 10 65 00 00 00 0c 00 6e 20 85 00 20 00 0c 00 12 32 46 00 00 02 62 02 2b 00 6e 20 82 00 20 00 0c 00 21 13 21 04 12 05 12 06 12 07 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}