
rule Trojan_Win32_CryptInject_AO_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.AO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 55 fc 8d 84 02 90 01 02 00 00 8b 4d 08 03 01 8b 55 08 89 02 8b 45 08 8b 08 81 e9 90 01 02 00 00 8b 55 08 89 0a 8b e5 5d c3 90 00 } //1
		$a_02_1 = {8b ff c7 05 90 01 03 00 00 00 00 00 a1 90 01 03 00 01 05 90 01 03 00 8b ff 8b 15 90 01 03 00 a1 90 01 03 00 89 02 5f 5d c3 90 0a 4f 00 b8 90 01 03 00 a1 90 01 03 00 31 0d 90 01 03 00 8b ff c7 05 90 01 03 00 00 00 00 00 a1 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}