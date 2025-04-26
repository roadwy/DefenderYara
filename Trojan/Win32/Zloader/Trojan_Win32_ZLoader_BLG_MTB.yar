
rule Trojan_Win32_ZLoader_BLG_MTB{
	meta:
		description = "Trojan:Win32/ZLoader.BLG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 f0 c1 e0 04 01 f0 b9 01 00 00 00 29 c1 03 0d ?? ?? ?? ?? 0f b6 5c 0f ff 8b 4d ec 41 8b 45 08 32 1c 38 8b 45 0c 88 1c 38 8d 7f 01 74 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}