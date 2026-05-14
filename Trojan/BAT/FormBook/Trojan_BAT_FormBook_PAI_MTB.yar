
rule Trojan_BAT_FormBook_PAI_MTB{
	meta:
		description = "Trojan:BAT/FormBook.PAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {08 11 09 11 0a 28 ?? 00 00 06 13 0b 07 11 06 12 0b 28 ?? 00 00 0a 9c 11 06 17 58 13 06 11 0d 20 6c d5 50 29 5a 20 79 a0 dc 1c 61 38 32 fe ff ff 02 } //3
		$a_81_1 = {53 69 6d 75 6c 61 74 69 6f 6e } //1 Simulation
		$a_81_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_03_0  & 1)*3+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=5
 
}