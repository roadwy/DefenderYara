
rule Trojan_BAT_CryptInject_MBAI_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.MBAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 11 04 11 05 9a 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 00 11 05 17 d6 13 05 11 05 11 07 13 08 11 08 31 d4 } //1
		$a_01_1 = {4a 06 4a 06 28 06 0d 00 33 06 4a 06 0d 00 2e 06 3a 06 0d 00 2e 06 3a 06 0d 00 2d 06 2d 06 0d 00 2e 06 3a 06 0d 00 2e 06 3a 06 0d 00 2e 06 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}