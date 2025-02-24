
rule Trojan_BAT_Marsilia_MBQ_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.MBQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {04 06 07 07 07 5f 60 91 06 07 91 61 06 07 91 61 d2 } //2
		$a_01_1 = {06 07 03 07 04 58 91 9c 00 07 17 58 0b 07 06 8e 69 fe 04 0c 08 2d e8 } //2
		$a_01_2 = {4c 00 6f 00 61 00 64 00 } //1 Load
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=3
 
}