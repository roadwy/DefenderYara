
rule Trojan_BAT_CryptInject_OJ_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.OJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 02 8e 69 7e 21 00 00 04 20 ea 00 00 00 7e 21 00 00 04 20 ea 00 00 00 91 03 61 20 b3 00 00 00 5f 9c 32 07 18 0c 38 15 ff ff ff 1d 2b f7 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}