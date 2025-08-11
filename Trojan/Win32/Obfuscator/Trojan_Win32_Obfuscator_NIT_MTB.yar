
rule Trojan_Win32_Obfuscator_NIT_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 00 6a 00 ff 15 14 81 40 00 c7 45 d4 00 00 00 00 6a 00 6a 00 ff 15 18 81 40 00 85 c0 0f 85 e9 00 00 00 c7 45 d0 00 00 00 00 c7 45 cc 00 00 00 00 eb 09 8b 4d cc 83 c1 01 89 4d cc 81 7d cc fb 0c 00 00 7d 0b 8b 55 d0 83 c2 01 89 55 d0 eb e3 6a 00 ff 15 34 80 40 00 83 f8 4b } //2
		$a_01_1 = {8b 4d fc 03 4d e8 8a 11 02 55 80 8b 45 fc 03 45 e8 88 10 8b 8d 74 ff ff ff 83 c1 01 89 8d 74 ff ff ff 8b 55 e0 81 e2 ff 00 00 00 39 95 74 ff ff ff } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}