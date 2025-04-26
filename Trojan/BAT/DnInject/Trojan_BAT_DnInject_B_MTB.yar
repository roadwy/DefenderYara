
rule Trojan_BAT_DnInject_B_MTB{
	meta:
		description = "Trojan:BAT/DnInject.B!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {0a 28 09 00 00 06 28 18 00 00 06 0a 06 28 0d 00 00 06 2a } //1
		$a_01_1 = {00 79 65 61 00 } //1
		$a_01_2 = {00 6c 6f 61 64 6d 65 00 } //1 氀慯浤e
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}