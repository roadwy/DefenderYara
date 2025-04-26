
rule Trojan_BAT_Remcos_MBXT_MTB{
	meta:
		description = "Trojan:BAT/Remcos.MBXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {4c 00 6f 00 61 00 64 [0-08] 44 00 75 00 6d 00 6d 00 79 00 43 00 70 00 70 00 43 00 6f 00 6d 00 70 00 69 00 6c 00 65 00 72 } //3
		$a_01_1 = {53 70 6c 69 74 } //2 Split
		$a_01_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}