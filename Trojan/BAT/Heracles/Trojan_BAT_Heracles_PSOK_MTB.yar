
rule Trojan_BAT_Heracles_PSOK_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PSOK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 98 00 00 0a 0a 02 72 a3 05 00 70 6f 90 01 03 0a 2c 3e 06 02 6f 90 01 03 0a 0b 07 16 73 90 01 03 0a 0c 73 90 01 03 0a 0d 08 09 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}