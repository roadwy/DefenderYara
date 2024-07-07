
rule Trojan_BAT_Redline_GDA_MTB{
	meta:
		description = "Trojan:BAT/Redline.GDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 06 11 04 6f 90 01 03 0a 13 05 11 05 16 fe 04 16 fe 01 13 08 11 08 2d 12 00 08 12 04 28 90 01 03 0a 28 90 01 03 0a 0c 00 2b 20 00 07 11 05 58 03 58 07 5d 13 06 08 06 11 06 6f 90 01 03 0a 8c 90 01 04 28 90 01 03 0a 0c 00 00 09 17 58 0d 09 02 6f 90 01 03 0a fe 04 13 08 11 08 2d 98 90 00 } //10
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}