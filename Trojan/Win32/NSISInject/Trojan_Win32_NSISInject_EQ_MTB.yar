
rule Trojan_Win32_NSISInject_EQ_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.EQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 8b 55 f4 52 6a 00 ff 15 } //5
		$a_01_1 = {89 54 24 04 c7 44 24 08 00 30 00 00 c7 44 24 0c 40 00 00 00 89 4d c4 ff d0 } //5
		$a_03_2 = {8b 45 f8 03 45 fc [0-0f] 8b 55 f8 03 55 fc 88 0a e9 ?? ?? ?? ?? 8b 45 f8 ff e0 8b e5 5d c2 10 00 } //1
		$a_03_3 = {88 14 08 8b 45 d0 83 c0 01 89 45 d0 e9 ?? ?? ?? ?? 8b 45 e8 ff e0 83 c4 50 5e 5f 5b 5d c3 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=6
 
}