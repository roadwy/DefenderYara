
rule Trojan_Win32_ZCrypren_A_MTB{
	meta:
		description = "Trojan:Win32/ZCrypren.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 84 24 7c 08 00 00 99 6a 0c 59 f7 f9 8b 4c 24 20 0f b6 c9 03 c1 b9 ?? ?? ?? ?? 2b 44 24 1c 0f b6 c9 03 4c 24 0c 03 c1 89 44 24 0c 33 ff 8b 4c 24 20 8b 74 24 10 0f b7 c1 03 c6 74 2c 33 d2 c7 44 24 3c 0f 00 00 00 8b c6 f7 74 24 3c 8d 94 24 7c 08 00 00 2b c8 0f b7 c2 2b c8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}