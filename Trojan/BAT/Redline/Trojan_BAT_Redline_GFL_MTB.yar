
rule Trojan_BAT_Redline_GFL_MTB{
	meta:
		description = "Trojan:BAT/Redline.GFL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f 00 08 20 00 04 00 00 58 28 90 01 03 2b 07 02 08 20 00 04 00 00 6f 90 01 03 0a 0d 08 09 58 0c 09 20 00 04 00 00 2f d8 0f 00 08 90 00 } //10
		$a_01_1 = {45 77 76 76 44 69 68 76 51 77 45 76 4c 78 79 69 4d 44 72 78 } //1 EwvvDihvQwEvLxyiMDrx
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}