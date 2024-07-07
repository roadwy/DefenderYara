
rule Trojan_BAT_Injector_SJ_bit{
	meta:
		description = "Trojan:BAT/Injector.SJ!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6c 00 6f 00 73 00 74 00 20 00 79 00 6f 00 75 00 72 00 20 00 67 00 61 00 6d 00 65 00 } //1 lost your game
		$a_03_1 = {4c 00 6f 00 73 00 74 00 90 02 10 50 00 6c 00 61 00 79 00 90 02 10 57 00 69 00 6e 00 90 00 } //1
		$a_03_2 = {06 11 04 06 11 04 91 90 01 01 11 04 07 5d 91 61 9c 11 04 17 d6 13 04 90 00 } //1
		$a_01_3 = {02 03 04 16 04 8e b7 28 3a 00 00 0a 06 2a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}