
rule Trojan_BAT_NjRat_NEBK_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 05 08 17 28 90 01 01 00 00 0a 11 06 08 17 28 90 01 01 00 00 0a 11 07 08 17 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 13 04 08 17 d6 0c 00 08 09 fe 02 16 fe 01 13 09 11 09 2d ca 28 90 01 01 00 00 0a 11 04 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 90 00 } //10
		$a_01_1 = {45 00 6e 00 74 00 72 00 79 00 50 00 6f 00 69 00 6e 00 74 00 } //2 EntryPoint
		$a_01_2 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //2 Invoke
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=14
 
}