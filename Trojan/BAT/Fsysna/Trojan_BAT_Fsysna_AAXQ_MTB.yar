
rule Trojan_BAT_Fsysna_AAXQ_MTB{
	meta:
		description = "Trojan:BAT/Fsysna.AAXQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0d 16 13 04 2b 3b 09 11 04 9a 0a 00 00 06 19 18 73 1a 00 00 0a 0b 07 73 1b 00 00 0a 0c 08 02 7b 01 00 00 04 6f } //2
		$a_01_1 = {44 00 72 00 61 00 67 00 74 00 6f 00 72 00 } //1 Dragtor
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}