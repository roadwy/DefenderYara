
rule Trojan_Win32_Jaik_NIT_MTB{
	meta:
		description = "Trojan:Win32/Jaik.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 70 0c 68 f0 00 00 00 ff 74 24 14 56 ff 15 f8 f2 4a 00 3b c7 74 19 50 56 ff 15 fc f2 4a 00 3b c7 75 04 33 c0 eb 11 50 ff 15 00 f3 4a 00 8b f8 57 8b cb e8 } //2
		$a_01_1 = {8b 86 d0 00 00 00 8d 54 24 1c 50 50 52 c7 44 24 44 00 00 00 00 e8 11 f9 ff ff 8b 46 4c 8b 4e 48 83 c0 64 83 c4 0c 83 c1 64 89 44 24 08 8d 44 24 04 89 4c 24 04 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}