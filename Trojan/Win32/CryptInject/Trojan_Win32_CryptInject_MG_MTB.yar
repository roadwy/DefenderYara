
rule Trojan_Win32_CryptInject_MG_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c7 85 7c ff ff ff 04 00 00 00 8d 55 fc 52 68 95 0c 00 00 68 90 01 04 ff 75 f8 ff 75 e8 ff 15 90 00 } //1
		$a_03_1 = {8b 1e c1 e3 04 03 5f 08 8b 06 01 d0 31 c3 8b 06 c1 e8 05 03 47 0c 31 c3 29 5e 04 8b 5e 04 c1 e3 04 03 1f 8b 46 04 01 d0 31 c3 8b 46 04 c1 e8 05 03 47 04 31 c3 29 1e 81 c2 90 01 04 49 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}