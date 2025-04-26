
rule Trojan_BAT_Cymulate_ACY_MTB{
	meta:
		description = "Trojan:BAT/Cymulate.ACY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 16 0b 02 28 6d 00 00 0a 16 fe 01 0c 08 2c 61 00 02 28 5a 00 00 0a 0d 09 2c 51 00 00 02 73 6e 00 00 0a 03 04 05 28 6f 00 00 0a 25 0a 13 04 00 06 16 6a 16 6a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}