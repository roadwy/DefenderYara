
rule Trojan_BAT_Cerbu_AC_MTB{
	meta:
		description = "Trojan:BAT/Cerbu.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 06 17 6f 5f 00 00 0a 06 03 6f 60 00 00 0a 06 04 6f 61 00 00 0a 73 62 00 00 0a 0b 06 6f 67 00 00 0a 0c 07 08 17 73 64 00 00 0a 0d 02 28 1e 00 00 06 13 04 09 11 04 16 11 04 8e 69 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}