
rule Trojan_BAT_Scarsi_ASI_MTB{
	meta:
		description = "Trojan:BAT/Scarsi.ASI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1e 2d 14 26 06 18 5b 8d 90 01 03 01 18 2d 0b 26 16 1a 2d 09 26 2b 21 0a 2b ea 0b 2b f3 0c 2b f5 07 08 18 5b 02 08 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 9c 08 18 58 0c 08 06 32 e4 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}