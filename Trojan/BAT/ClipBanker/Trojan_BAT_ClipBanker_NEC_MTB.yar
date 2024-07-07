
rule Trojan_BAT_ClipBanker_NEC_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.NEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 01 01 00 0a 6f 02 01 00 0a 13 0c 08 28 0d 00 00 0a 2d 10 08 11 0c 28 03 01 00 0a 16 13 16 dd bc 02 00 00 11 05 11 0c 6f 04 01 00 0a 26 14 13 0d 72 0d 03 01 70 73 05 01 00 0a 13 0e 11 08 13 0f } //1
		$a_01_1 = {2d 00 65 00 78 00 74 00 64 00 75 00 6d 00 6d 00 74 00 } //1 -extdummt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}