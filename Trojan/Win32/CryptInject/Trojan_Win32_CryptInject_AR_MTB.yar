
rule Trojan_Win32_CryptInject_AR_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 4d fc 83 c1 01 89 4d fc 81 7d fc 90 01 02 00 00 73 2a 8b 45 fc 33 d2 b9 04 00 00 00 f7 f1 8b 45 f0 0f be 0c 10 8b 55 fc 0f b6 82 00 50 44 00 33 c1 8b 4d fc 88 81 00 50 44 00 eb c4 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}