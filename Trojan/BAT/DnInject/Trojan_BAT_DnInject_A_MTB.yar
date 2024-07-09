
rule Trojan_BAT_DnInject_A_MTB{
	meta:
		description = "Trojan:BAT/DnInject.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_02_0 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 [0-20] 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 6d 00 61 00 7a 00 65 00 2e 00 74 00 78 00 74 00 } //1
		$a_00_1 = {54 68 69 73 2b 70 72 6f 67 72 61 6d 2b 63 61 6e 6e 6f 74 2b 62 65 2b 72 75 6e 2b 69 6e 2b 44 4f 53 2b 6d 6f 64 65 } //1 This+program+cannot+be+run+in+DOS+mode
		$a_00_2 = {67 65 74 5f 69 69 69 } //1 get_iii
		$a_00_3 = {42 00 20 00 75 00 20 00 74 00 20 00 61 00 } //1 B u t a
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}