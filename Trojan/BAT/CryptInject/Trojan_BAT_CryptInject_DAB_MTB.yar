
rule Trojan_BAT_CryptInject_DAB_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.DAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {1a 8d 05 00 00 01 0c 07 08 16 1a 6f 0d 00 00 0a 26 08 16 28 0e 00 00 0a 26 07 16 73 0f 00 00 0a 0d 09 06 6f 10 00 00 0a 06 6f 0a 00 00 0a 13 04 dd 27 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}