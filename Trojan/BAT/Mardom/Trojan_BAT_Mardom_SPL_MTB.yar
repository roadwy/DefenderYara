
rule Trojan_BAT_Mardom_SPL_MTB{
	meta:
		description = "Trojan:BAT/Mardom.SPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 3d 11 3e 16 9e 00 11 3e 17 58 13 3e 11 3e 11 3d 8e 69 fe 04 13 3f 11 3f 3a e1 ff ff ff } //1
		$a_01_1 = {5f 41 4c 56 67 61 65 77 44 69 77 61 64 61 } //1 _ALVgaewDiwada
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}