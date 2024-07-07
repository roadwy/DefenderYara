
rule Trojan_Win32_CryptInject_PB_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 51 8b 45 0c 89 45 fc 8b 0d 90 01 04 89 4d 08 8b 55 08 8b 02 8b 4d fc 8d 94 01 8a 10 00 00 8b 45 08 89 10 8b 4d 08 8b 11 81 ea 8a 10 00 00 8b 45 08 89 10 8b e5 5d c3 90 00 } //1
		$a_02_1 = {55 8b ec 57 90 02 20 8b 0d 90 01 04 8b 11 89 15 90 01 04 a1 90 01 04 90 02 20 a3 90 01 04 8b ff 90 02 40 8b ca 90 08 00 02 31 0d 90 01 04 a1 90 01 04 8b ff c7 05 90 01 04 00 00 00 00 01 05 90 01 04 8b ff 8b 0d 90 01 04 8b 15 90 01 04 89 11 5f 5d c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}