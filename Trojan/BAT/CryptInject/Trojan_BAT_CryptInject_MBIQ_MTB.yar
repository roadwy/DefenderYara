
rule Trojan_BAT_CryptInject_MBIQ_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.MBIQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 00 79 00 00 2d 45 00 38 00 46 00 37 00 44 00 42 00 4a 00 37 00 59 00 42 00 47 00 35 00 47 00 38 00 37 00 46 00 56 00 38 00 31 00 49 00 54 00 5a 00 } //1 HyⴀE8F7DBJ7YBG5G87FV81ITZ
		$a_01_1 = {44 00 6f 00 64 00 67 00 65 00 00 0d 49 00 6e 00 76 00 6f 00 6b 00 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}