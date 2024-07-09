
rule Trojan_BAT_CryptInject_MBHZ_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.MBHZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 8e b7 17 da 13 04 0d 2b 2b 08 07 09 9a 28 ?? 00 00 0a 17 6a 61 28 ?? 00 00 0a 18 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0c 09 17 d6 0d 09 11 04 31 d0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}