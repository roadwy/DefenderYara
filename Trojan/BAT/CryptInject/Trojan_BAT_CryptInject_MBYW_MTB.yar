
rule Trojan_BAT_CryptInject_MBYW_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.MBYW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 00 4b 00 75 00 45 00 74 00 36 00 6d 00 6d 00 2f 00 30 00 4d 00 70 00 2b 00 4a 00 2b 00 65 00 6e 00 5a 00 4a 00 34 00 67 00 72 00 47 00 33 00 72 00 77 00 4e 00 65 00 64 00 48 00 6a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}