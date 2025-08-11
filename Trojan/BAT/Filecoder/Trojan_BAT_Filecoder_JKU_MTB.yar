
rule Trojan_BAT_Filecoder_JKU_MTB{
	meta:
		description = "Trojan:BAT/Filecoder.JKU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {09 08 16 08 8e 69 6f 38 00 00 0a 09 07 07 6f 39 00 00 0a 08 6f 3a 00 00 0a 17 73 3b 00 00 0a 13 04 03 19 73 37 00 00 0a 13 05 11 05 11 04 6f 3c 00 00 0a de 0c } //2
		$a_01_1 = {06 72 67 04 00 70 6f 30 00 00 0a 28 31 00 00 0a 0b de 0a 06 2c 06 06 6f 2a 00 00 0a dc } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}