
rule Trojan_BAT_Redline_GUC_MTB{
	meta:
		description = "Trojan:BAT/Redline.GUC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {09 11 04 16 11 04 8e 69 28 90 01 03 06 13 05 7e 90 01 04 07 11 04 16 11 05 28 90 01 03 06 00 00 11 05 16 fe 02 13 06 11 06 2d ce 90 00 } //10
		$a_01_1 = {54 6e 70 6d 70 6a 6b 75 6e 66 79 7a 66 7a 62 79 70 } //1 Tnpmpjkunfyzfzbyp
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}