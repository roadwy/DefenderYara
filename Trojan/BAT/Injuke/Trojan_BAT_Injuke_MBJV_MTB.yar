
rule Trojan_BAT_Injuke_MBJV_MTB{
	meta:
		description = "Trojan:BAT/Injuke.MBJV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {da 04 d6 1f 1a 5d 13 07 11 0b } //1
		$a_01_1 = {7d 00 00 03 7d 00 00 03 30 00 00 0f 20 00 4c 00 6f 00 2d 00 61 00 64 00 20 00 00 03 2d 00 00 11 44 00 65 00 6c 00 65 00 74 00 65 00 4d 00 43 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}