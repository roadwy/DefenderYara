
rule Trojan_BAT_Vidar_NNI_MTB{
	meta:
		description = "Trojan:BAT/Vidar.NNI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {6f a5 00 00 0a 0d 1a 13 0f 38 90 01 03 ff 08 11 08 08 11 08 91 11 04 11 08 09 5d 91 61 d2 9c 1f 1e 28 90 01 03 06 90 00 } //5
		$a_01_1 = {66 65 64 65 72 61 6c 75 6e 64 65 72 73 74 61 6e 64 69 6e 67 } //1 federalunderstanding
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}