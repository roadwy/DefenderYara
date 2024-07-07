
rule Trojan_BAT_Vidar_AADB_MTB{
	meta:
		description = "Trojan:BAT/Vidar.AADB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 59 0a 06 20 10 0e 00 00 6a 5b 1f 18 6a 5d 80 90 01 01 00 00 04 06 20 10 0e 00 00 6a 59 0a 08 07 6f 90 01 01 00 00 0a 17 73 90 01 01 00 00 0a 0d 09 02 16 02 8e 69 6f 90 01 01 00 00 0a 06 1f 3c 6a 59 0a 06 1f 3c 6a 5d 80 90 01 01 00 00 04 09 6f 90 01 01 00 00 0a de 07 09 6f 90 01 01 00 00 0a dc 08 6f 90 01 01 00 00 0a 13 04 de 0e 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}