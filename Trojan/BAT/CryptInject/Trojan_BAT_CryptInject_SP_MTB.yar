
rule Trojan_BAT_CryptInject_SP_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {3a 5c 78 61 6d 70 70 5c 68 74 64 6f 63 73 5c 41 73 70 69 72 65 5c 66 69 6c 65 73 5c 90 02 40 2e 70 64 62 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}