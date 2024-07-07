
rule Trojan_BAT_Injector_Y_bit{
	meta:
		description = "Trojan:BAT/Injector.Y!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {4d 00 6f 00 5f 00 6e 00 69 00 2e 00 50 00 6e 00 67 00 90 02 10 4b 00 69 00 6d 00 5f 00 4f 00 2e 00 50 00 6e 00 67 00 90 02 10 4c 00 6f 00 61 00 64 00 90 00 } //1
		$a_03_1 = {8e b7 17 da 11 04 da 02 11 04 91 90 01 01 61 90 01 01 11 04 90 01 01 8e b7 5d 91 61 9c 11 04 17 d6 13 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}