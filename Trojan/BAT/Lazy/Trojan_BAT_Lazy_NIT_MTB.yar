
rule Trojan_BAT_Lazy_NIT_MTB{
	meta:
		description = "Trojan:BAT/Lazy.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {fe 0c 01 00 fe 0c 02 00 6f bc 00 00 0a fe 0e 03 00 00 fe 0c 00 00 fe 0c 03 00 20 58 00 00 00 61 d1 6f bd 00 00 0a 26 00 fe 0c 02 00 20 01 00 00 00 58 fe 0e 02 00 fe 0c 02 00 fe 0c 01 00 6f be 00 00 0a 3f b8 ff ff ff fe 0c 00 00 6f 17 00 00 0a fe 0e 04 00 38 00 00 00 00 fe 0c 04 00 2a } //2
		$a_01_1 = {28 46 00 00 0a 6f 51 00 00 0a 0b 06 07 1f 42 28 37 00 00 06 28 52 00 00 0a 07 0c de 13 26 14 0c de 0e 06 28 53 00 00 0a 1f 42 28 37 00 00 06 2a } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}