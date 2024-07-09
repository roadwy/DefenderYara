
rule Trojan_BAT_CryptInject_MBJM_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.MBJM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 08 11 0c 11 0a 6f ?? 00 00 0a 13 0b 11 06 09 19 d8 18 d6 12 0b 28 ?? 00 00 0a 9c 11 06 09 19 d8 17 d6 12 0b 28 ?? 00 00 0a 9c 11 06 09 19 d8 12 0b 28 ?? 00 00 0a 9c 09 17 d6 0d 11 0c 17 d6 13 0c 11 0c 11 0e 31 b8 } //1
		$a_01_1 = {1a 04 29 04 1a 04 39 04 13 04 26 04 16 04 7a 04 43 04 1b 04 41 04 47 04 } //1 КЩКйГЦЖѺуЛсч
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}