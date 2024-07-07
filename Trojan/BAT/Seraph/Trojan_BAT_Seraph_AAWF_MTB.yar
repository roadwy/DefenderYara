
rule Trojan_BAT_Seraph_AAWF_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AAWF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 14 fe 90 01 02 00 00 06 73 90 01 01 00 00 0a 28 90 01 01 00 00 06 17 2c ec 28 90 01 01 00 00 06 75 90 01 01 00 00 1b 73 90 01 01 00 00 0a 0d 09 07 16 73 90 01 01 00 00 0a 13 04 11 04 08 16 2c 16 26 26 7e 90 01 01 00 00 04 08 6f 90 01 01 00 00 0a 14 16 2c 0c 26 26 26 de 34 6f 90 01 01 00 00 0a 2b e5 6f 90 01 01 00 00 0a 2b f0 11 04 2c 07 11 04 6f 90 01 01 00 00 0a dc 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}