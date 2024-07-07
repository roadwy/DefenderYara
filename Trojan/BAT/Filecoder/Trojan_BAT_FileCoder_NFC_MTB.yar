
rule Trojan_BAT_FileCoder_NFC_MTB{
	meta:
		description = "Trojan:BAT/FileCoder.NFC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {7e 42 01 00 04 7e 90 01 02 00 04 28 90 01 02 00 06 11 08 11 09 11 0b 11 09 59 28 90 01 02 00 06 17 8d 90 01 02 00 01 28 90 01 02 00 06 6f 90 01 02 00 0a 11 0b 17 58 13 09 11 0b 17 90 00 } //5
		$a_01_1 = {4d 4c 2e 4e 45 54 20 50 72 6f 67 72 61 6d } //1 ML.NET Program
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}