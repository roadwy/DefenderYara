
rule Trojan_Win32_CryptInject_BX_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.BX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 75 fc 03 f7 8a 03 88 45 fa 57 58 51 6a 03 59 60 61 33 d2 f7 f1 59 09 d2 75 11 8a 45 fa 32 45 f9 88 06 8a 06 32 45 fb 88 06 eb 05 8a 45 fa 88 06 47 43 49 75 ca 8b 7d ec 8b 75 f0 8b 5d f4 55 5c 5d c2 08 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}