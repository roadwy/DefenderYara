
rule Trojan_BAT_CryptInject_DAA_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.DAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 09 02 09 6f 2a 00 00 0a 03 09 07 5d 6f 2a 00 00 0a 61 d1 9d 09 17 58 0d 09 06 32 e3 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}