
rule Trojan_BAT_Remcos_PL_MTB{
	meta:
		description = "Trojan:BAT/Remcos.PL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {28 03 00 00 0a 72 01 00 00 70 6f 04 00 00 0a 0a 06 6f 05 00 00 0a d4 8d 06 00 00 01 0b 06 07 16 07 8e 69 6f 06 00 00 0a 26 07 72 13 00 00 70 28 02 00 00 06 0b 07 28 07 00 00 0a 6f 08 00 00 0a 14 14 6f 09 00 00 0a 26 de 0a 06 2c 06 06 6f 0a 00 00 0a dc 2a } //1
		$a_81_1 = {54 65 6d 70 46 69 6c 65 } //1 TempFile
		$a_81_2 = {23 50 41 53 53 57 4f 52 44 } //1 #PASSWORD
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}