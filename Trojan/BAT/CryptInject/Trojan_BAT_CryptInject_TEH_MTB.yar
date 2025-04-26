
rule Trojan_BAT_CryptInject_TEH_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.TEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 12 03 28 55 00 00 0a 73 80 00 00 0a 13 04 20 20 00 00 02 28 ec 03 00 06 28 6a 00 00 0a 6f 6b 00 00 0a 72 54 4e 00 70 6f 62 00 00 0a 73 7f 00 00 0a 25 6f 7a 00 00 0a 16 6a 6f 63 00 00 0a 25 25 6f 7a 00 00 0a 6f 64 00 00 0a 69 6f 81 00 00 0a 13 05 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}