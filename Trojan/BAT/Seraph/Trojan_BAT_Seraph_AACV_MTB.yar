
rule Trojan_BAT_Seraph_AACV_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AACV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 1a 8d 90 01 01 00 00 01 0c 07 08 16 1a 6f 90 01 01 00 00 0a 26 08 16 28 90 01 01 00 00 0a 0d 07 16 73 90 01 01 00 00 0a 13 04 09 8d 90 01 01 00 00 01 13 05 11 04 11 05 16 09 6f 90 01 01 00 00 0a 26 11 05 13 06 dd 90 01 01 00 00 00 11 04 39 90 01 01 00 00 00 11 04 6f 90 01 01 00 00 0a dc 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}