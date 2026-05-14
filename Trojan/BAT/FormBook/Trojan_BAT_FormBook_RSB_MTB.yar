
rule Trojan_BAT_FormBook_RSB_MTB{
	meta:
		description = "Trojan:BAT/FormBook.RSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {57 9d a2 29 09 0f 00 00 00 00 00 00 00 00 00 00 02 00 00 00 c9 00 00 00 52 00 00 00 ?? 01 00 00 df 01 00 00 3d 01 00 00 76 02 00 00 04 00 00 00 cc 00 00 00 0c 00 00 00 74 00 00 00 0f 00 00 00 2c 00 00 00 33 00 00 00 84 00 00 00 0f 00 00 00 02 00 00 00 07 00 00 00 06 00 00 00 37 00 00 00 21 00 00 00 3e } //1
		$a_81_1 = {4d 61 67 6e 65 74 69 63 56 69 73 75 61 6c 69 7a 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 MagneticVisualizer.Properties.Resources
		$a_81_2 = {67 65 74 5f 54 4d } //1 get_TM
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}