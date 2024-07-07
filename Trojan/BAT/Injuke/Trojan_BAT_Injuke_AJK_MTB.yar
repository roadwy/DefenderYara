
rule Trojan_BAT_Injuke_AJK_MTB{
	meta:
		description = "Trojan:BAT/Injuke.AJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 0b 2b 1b 00 7e 01 00 00 04 07 7e 01 00 00 04 07 91 20 56 02 00 00 59 d2 9c 00 07 17 58 0b 07 7e 01 00 00 04 8e 69 fe 04 0c 08 2d d7 } //2
		$a_01_1 = {4a 4f 4b 41 46 57 41 49 55 46 48 } //1 JOKAFWAIUFH
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}