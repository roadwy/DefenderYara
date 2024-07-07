
rule Trojan_Win32_CryptInject_DZ_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.DZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 00 33 d0 33 8c 95 90 02 04 89 4d fc 8b 4d ec 83 c1 01 89 4d ec eb 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}