
rule Trojan_BAT_Redline_MVA_MTB{
	meta:
		description = "Trojan:BAT/Redline.MVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 75 0c 00 00 1b 07 17 da 20 05 b6 2c 6d 1e 16 28 23 00 00 06 28 b5 02 00 06 09 28 e2 02 00 06 28 33 00 00 0a a2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}