
rule Trojan_Win32_CryptInject_YJ_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.YJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f be 04 3e 89 ?? 24 0c e8 ?? f6 ff ff 89 44 24 10 8b 44 24 0c 33 44 24 10 89 44 24 0c 8a 4c 24 0c 88 0c 3e 46 3b f3 7c d7 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}