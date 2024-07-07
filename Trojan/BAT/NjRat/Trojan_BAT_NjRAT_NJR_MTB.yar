
rule Trojan_BAT_NjRAT_NJR_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.NJR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {5a 13 0e 11 0e 11 08 61 11 04 06 61 20 90 01 03 0c 6e 5a 58 13 0e 17 13 0f 38 90 01 03 ff d0 90 01 03 02 20 90 01 03 22 20 90 01 03 2e 58 13 0f 26 90 00 } //5
		$a_01_1 = {79 67 54 66 4d 4f 5a } //1 ygTfMOZ
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}