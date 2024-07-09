
rule Trojan_BAT_CryptInject_AD_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {28 10 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 0a fe ?? 00 00 fe ?? 00 00 28 ?? 00 00 06 dd ?? 00 00 00 26 dd 00 00 00 00 2a } //1
		$a_02_1 = {28 10 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 06 28 ?? 00 00 06 de ?? 26 de 00 2a } //1
		$a_02_2 = {7e 0c 00 00 04 28 0f 00 00 06 28 ?? 00 00 0a 28 06 00 00 0a } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}
rule Trojan_BAT_CryptInject_AD_MTB_2{
	meta:
		description = "Trojan:BAT/CryptInject.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {72 f2 00 00 70 28 ?? 00 00 06 13 05 72 ?? 00 00 70 28 ?? 00 00 06 13 06 72 ?? 00 00 70 28 ?? 00 00 06 13 07 72 ?? 00 00 70 28 ?? 00 00 06 13 08 08 1b 8d ?? 00 00 01 } //1
		$a_02_1 = {1f 49 13 0e 12 0e 28 ?? 00 00 0a 28 ?? 00 00 06 13 05 1f 45 13 0e 12 0e 28 ?? 00 00 0a 28 ?? 00 00 06 13 06 1f 41 13 0e 12 0e 28 ?? 00 00 0a 28 ?? 00 00 06 13 07 1f 3d 13 0e 12 0e 28 ?? 00 00 0a 28 ?? 00 00 06 13 08 08 1b 8d ?? 00 00 01 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}