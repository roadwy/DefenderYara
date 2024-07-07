
rule Trojan_Win32_CryptInject_DV_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.DV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 d8 83 e0 1f 8a 80 24 50 40 00 30 04 1e c7 44 24 0c 00 00 00 00 c7 44 24 08 00 00 00 00 c7 44 24 04 00 00 00 00 c7 04 24 00 00 00 00 e8 90 02 04 83 ec 10 e8 90 02 04 30 04 1e c7 44 24 0c 00 00 00 00 c7 44 24 08 00 00 00 00 c7 44 24 04 00 00 00 00 c7 04 24 00 00 00 00 e8 90 02 04 83 ec 10 43 39 fb 75 97 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}