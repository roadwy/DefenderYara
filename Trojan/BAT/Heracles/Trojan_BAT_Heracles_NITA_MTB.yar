
rule Trojan_BAT_Heracles_NITA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.NITA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {17 8d 02 00 00 01 25 16 72 23 03 00 70 7e 06 00 00 04 72 55 03 00 70 28 02 00 00 0a a2 28 4f 00 00 0a 73 50 00 00 0a 25 72 87 03 00 70 6f 51 00 00 0a 25 72 bf 03 00 70 72 01 03 00 70 28 4d 00 00 0a 72 0b 03 00 70 28 02 00 00 0a 6f 52 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}