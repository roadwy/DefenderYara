
rule Trojan_Win32_NativeZone_C_dha{
	meta:
		description = "Trojan:Win32/NativeZone.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {5a 4d 52 41 48 55 e5 89 81 48 20 ec 00 00 48 00 1d ?? ff ea ff ff 89 48 48 df c3 81 5f 88 00 01 d3 } //1
		$a_03_1 = {83 c0 02 89 44 24 ?? 8b 44 24 ?? 39 44 24 ?? 7d ?? 8b 44 24 ?? ff c0 48 98 48 8d 0d ?? ?? ?? ?? 48 63 54 24 ?? 48 8b 9c 24 ?? ?? ?? ?? 0f b6 04 01 88 04 13 48 63 44 24 ?? 48 8d 0d ?? ?? ?? ?? 8b 54 24 ?? ff c2 48 63 d2 48 8b 9c 24 ?? ?? ?? ?? 0f b6 04 01 88 04 13 } //1
		$a_03_2 = {43 3a 5c 55 73 65 72 73 5c 64 65 76 5c 44 65 73 6b 74 6f 70 5c eb 82 98 ed 83 80 eb 82 98 ea b2 8c 20 ed 95 98 eb 8b a4 5c 44 6c 6c ?? 5c 78 ?? ?? 5c 52 65 6c 65 61 73 65 5c 44 6c 6c ?? 2e 70 64 62 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}