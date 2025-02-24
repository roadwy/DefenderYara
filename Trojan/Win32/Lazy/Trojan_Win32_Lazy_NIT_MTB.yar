
rule Trojan_Win32_Lazy_NIT_MTB{
	meta:
		description = "Trojan:Win32/Lazy.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {6a 04 68 00 10 00 00 56 57 ff 15 00 d2 57 00 85 c0 74 1a 8d 45 ec 50 68 04 01 00 00 56 57 ff 15 38 d4 57 00 85 c0 } //2
		$a_01_1 = {68 0a 6f 55 00 ff 75 0c 6a 00 ff 15 28 d4 57 00 8b f8 85 ff 75 1e ff 15 10 d4 57 00 50 e8 78 e8 ff ff 59 83 cf ff 8d 4d fc e8 af fe ff ff 8b c7 5f 5e c9 c3 57 89 7e 08 ff 15 60 d3 57 00 83 f8 ff } //2
		$a_01_2 = {6a 00 6a 00 ff 15 10 da 57 00 6a 00 6a 00 6a 00 6a 03 6a 06 6a 00 6a 00 6a ff 6a 00 ff 15 0c da 57 00 8d 45 b4 50 68 30 88 5a 00 6a 01 6a 00 68 40 88 5a 00 ff 15 08 da 57 00 8b 35 ac d4 57 00 8d 85 00 ff ff ff } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}