
rule Trojan_BAT_CryptInject_NYZ_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.NYZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {57 ff a3 3f 09 0f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 ce 00 00 00 8b 05 00 00 56 0a 00 00 e0 17 00 00 a3 12 00 00 2a 00 00 00 6d 02 00 00 99 01 00 00 e3 00 00 00 1a 00 00 00 01 00 00 00 1a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}