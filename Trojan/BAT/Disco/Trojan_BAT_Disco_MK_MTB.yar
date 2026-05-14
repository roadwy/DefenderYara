
rule Trojan_BAT_Disco_MK_MTB{
	meta:
		description = "Trojan:BAT/Disco.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 28 18 00 00 06 0c 1a 08 8e 69 58 8d 16 00 00 01 0d 08 8e 69 28 4b 00 00 0a 09 16 6f 4f 00 00 0a 08 09 1a 6f 4f 00 00 0a 7e 05 00 00 04 09 16 09 8e 69 6f 4a 00 00 0a } //25
		$a_01_1 = {28 2d 00 00 06 26 25 11 06 28 29 00 00 06 26 11 05 28 2b 00 00 06 26 28 2c 00 00 06 26 7e 48 00 00 0a 11 04 28 25 00 00 06 26 73 49 00 00 0a 13 0a } //10
	condition:
		((#a_01_0  & 1)*25+(#a_01_1  & 1)*10) >=35
 
}