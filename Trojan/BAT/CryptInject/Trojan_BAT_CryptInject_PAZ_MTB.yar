
rule Trojan_BAT_CryptInject_PAZ_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.PAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 04 11 15 11 04 11 15 91 1f 7a 61 d2 9c 00 11 15 17 58 13 15 11 15 11 04 8e 69 fe 04 13 16 11 16 2d dc } //1
		$a_03_1 = {72 01 00 00 70 7e 0e 00 00 0a 7e 0e 00 00 0a 16 1a 7e 0e 00 00 0a 14 12 05 12 06 28 ?? ?? ?? 06 13 08 16 13 09 11 06 7b 18 00 00 04 13 0a 11 0a 16 12 07 28 ?? ?? ?? 0a 1c 5a 12 09 28 ?? ?? ?? 06 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}