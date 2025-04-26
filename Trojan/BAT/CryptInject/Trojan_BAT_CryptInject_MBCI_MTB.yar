
rule Trojan_BAT_CryptInject_MBCI_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.MBCI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 00 34 00 73 00 49 00 41 00 41 00 41 00 41 00 41 00 41 00 41 00 45 00 41 00 4e 00 53 00 39 00 43 00 32 00 78 00 72 00 61 00 33 00 62 00 66 00 39 00 2b 00 6b 00 38 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}