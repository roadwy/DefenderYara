
rule Trojan_Win32_Iceid_AK_MTB{
	meta:
		description = "Trojan:Win32/Iceid.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d1 ed 6a 00 5f 74 ?? 8d 58 ?? 0f b7 13 89 54 24 ?? 66 c1 6c 24 1c ?? 0f b7 d2 c7 44 24 ?? 00 10 00 00 66 3b 54 24 ?? 72 ?? 81 e2 ff 0f 00 00 03 51 04 03 10 66 83 7c 24 ?? 03 75 ?? 01 32 47 83 c3 02 3b fd 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Iceid_AK_MTB_2{
	meta:
		description = "Trojan:Win32/Iceid.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f af f7 44 31 ce 83 ce fe 6b c0 37 89 c7 81 c7 c3 f6 ff ff 48 63 ff 48 69 ff 09 04 02 81 48 c1 ef 20 01 c7 81 c7 c3 f6 ff ff 89 fb c1 eb 1f c1 ff 06 01 df 89 fb c1 e3 07 29 df 8d [0-81] c3 c3 f6 ff ff 01 f8 05 42 f7 ff ff 48 98 48 69 c0 09 04 02 81 48 c1 e8 20 01 d8 83 c0 7f 89 c7 c1 ef 1f c1 f8 06 01 f8 89 c7 c1 e7 07 29 f8 44 39 ce 0f ?? ?? ?? ?? 40 0f 94 c6 41 be 98 7e 19 44 45 0f 44 f7 41 83 fa 0a 0f ?? ?? ?? ?? 0f 9c c2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}