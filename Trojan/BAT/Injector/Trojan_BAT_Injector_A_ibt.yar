
rule Trojan_BAT_Injector_A_ibt{
	meta:
		description = "Trojan:BAT/Injector.A!ibt,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 28 90 01 04 02 07 69 9a 6f 90 01 04 74 90 01 04 0d 09 16 06 08 09 8e 69 17 59 28 90 01 04 08 09 8e 69 17 59 58 0c 07 23 00 00 00 00 00 00 f0 3f 58 0b 07 02 8e 69 6c 32 90 01 01 06 2a 90 00 } //1
		$a_03_1 = {06 07 06 07 91 1f 90 01 01 61 d2 9c 07 17 58 0b 07 06 8e 69 32 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}