
rule Trojan_BAT_AveMaria_NEFA_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_03_0 = {6f 59 00 00 0a 80 28 00 00 04 16 0b 2b 1b 00 7e 90 01 01 00 00 04 07 7e 90 01 01 00 00 04 07 91 20 90 01 02 00 00 59 d2 9c 00 07 17 58 0b 07 7e 90 01 01 00 00 04 8e 69 fe 04 0c 08 2d d7 7e 90 01 01 00 00 04 0d 2b 00 09 2a 90 00 } //10
		$a_01_1 = {53 65 69 6f 2e 70 64 62 } //5 Seio.pdb
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}