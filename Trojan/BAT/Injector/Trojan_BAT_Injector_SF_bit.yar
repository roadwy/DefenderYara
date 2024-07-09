
rule Trojan_BAT_Injector_SF_bit{
	meta:
		description = "Trojan:BAT/Injector.SF!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {7e 09 00 00 04 06 1f ?? 5d 91 07 1f 1f 5f 63 0d 09 20 ff 00 00 00 5f d2 13 04 7e 08 00 00 04 06 08 11 04 61 d2 9c 06 17 58 0a } //1
		$a_01_1 = {53 00 69 00 73 00 74 00 69 00 6d 00 65 00 74 00 6f 00 20 00 63 00 6f 00 75 00 64 00 6e 00 27 00 74 00 20 00 6c 00 6f 00 61 00 64 00 20 00 74 00 68 00 65 00 20 00 73 00 69 00 73 00 74 00 65 00 6d 00 } //1 Sistimeto coudn't load the sistem
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}