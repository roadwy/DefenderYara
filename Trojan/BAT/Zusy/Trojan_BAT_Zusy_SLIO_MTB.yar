
rule Trojan_BAT_Zusy_SLIO_MTB{
	meta:
		description = "Trojan:BAT/Zusy.SLIO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 9a 0c 08 16 17 6f 66 00 00 0a 12 03 28 67 00 00 0a 2c 20 72 ab 01 00 70 09 8c 3d 00 00 01 28 68 00 00 0a 28 12 00 00 0a 08 28 19 00 00 06 28 14 00 00 06 07 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}