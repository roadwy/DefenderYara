
rule Trojan_BAT_Redline_ARED_MTB{
	meta:
		description = "Trojan:BAT/Redline.ARED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {0a 06 18 5b 8d 34 00 00 01 0b 16 0c 2b 18 07 08 18 5b 02 08 18 6f 21 00 00 0a 1f 10 28 22 00 00 0a 9c 08 18 58 0c 08 06 32 e4 } //01 00 
		$a_03_1 = {06 0b 06 73 2e 00 00 0a 0c 08 07 6f 90 01 03 0a 16 73 30 00 00 0a 0d 06 8e 69 8d 34 00 00 01 13 04 09 11 04 16 11 04 8e 69 6f 90 01 03 0a 26 11 04 28 90 01 03 06 26 73 1f 00 00 06 17 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}