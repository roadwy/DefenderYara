
rule Trojan_Win32_UrsnifCrypt_SK_MTB{
	meta:
		description = "Trojan:Win32/UrsnifCrypt.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_02_0 = {56 8b f0 b8 ?? ?? ?? ?? 2b c6 50 8b c6 e8 ?? ?? ?? ?? 85 c0 74 34 8b 4e 3c 8b 54 31 08 81 f2 ?? ?? ?? ?? 74 20 8b 48 0c 8b 74 24 08 8b 40 10 89 0e 8b 74 24 0c 89 06 03 c1 8b 4c 24 10 33 c2 89 01 33 c0 eb 0a 33 c0 40 eb 05 } //2
		$a_02_1 = {53 56 57 6a 09 8b f8 33 db 5e 8b 07 8b ce 83 e1 01 c1 e1 03 d3 e0 83 c7 04 03 d8 4e 85 f6 74 12 56 ff 74 24 14 ff 15 ?? ?? ?? ?? 3d 02 01 00 00 74 d8 5f 5e 8b c3 5b c2 04 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=4
 
}