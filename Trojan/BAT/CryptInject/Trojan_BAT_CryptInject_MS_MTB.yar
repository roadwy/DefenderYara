
rule Trojan_BAT_CryptInject_MS_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.MS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 08 06 8e 69 5d 91 0d 07 08 02 08 91 09 61 d2 9c 08 17 58 0c 08 02 8e 69 32 e5 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}