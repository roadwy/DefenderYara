
rule Trojan_BAT_CryptInject_JYAA_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.JYAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {0c 08 66 0c 08 17 58 0c 08 66 0c 08 07 61 0c } //2
		$a_03_1 = {06 07 17 58 6f ?? 00 00 0a 28 ?? 00 00 0a 0a 07 17 58 0b } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}