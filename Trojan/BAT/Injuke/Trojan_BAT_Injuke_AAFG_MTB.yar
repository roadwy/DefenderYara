
rule Trojan_BAT_Injuke_AAFG_MTB{
	meta:
		description = "Trojan:BAT/Injuke.AAFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 06 6f 90 01 01 02 00 0a 06 6f 90 01 01 02 00 0a 6f 90 01 01 02 00 0a 13 04 73 90 01 01 02 00 0a 0b 02 73 90 01 01 02 00 0a 0c 08 11 04 16 73 90 01 01 02 00 0a 0d 09 07 6f 90 01 01 02 00 0a 07 6f 90 01 01 02 00 0a 13 05 de 1f 09 6f 90 01 01 00 00 0a dc 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}