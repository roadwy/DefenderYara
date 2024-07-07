
rule Trojan_BAT_NjRat_NECD_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NECD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 "
		
	strings :
		$a_01_0 = {7e d9 02 00 04 07 09 16 6f 58 00 00 0a 13 04 12 04 28 59 00 00 0a 6f 5a 00 00 0a 00 09 17 d6 0d 09 08 31 dc } //10
		$a_01_1 = {45 00 6e 00 74 00 72 00 79 00 50 00 6f 00 69 00 6e 00 74 00 } //2 EntryPoint
		$a_01_2 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //2 Invoke
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=14
 
}