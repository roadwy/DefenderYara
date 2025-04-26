
rule Trojan_BAT_CryptInject_MBYC_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.MBYC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 06 02 06 91 03 06 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 06 17 58 0a } //1
		$a_01_1 = {76 4d 65 4a 4c 34 79 74 4f } //1 vMeJL4ytO
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}