
rule Trojan_Win32_Emotet_DSI_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DSI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {81 e1 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 03 8a 54 14 ?? 32 c2 88 03 } //1
		$a_02_1 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8a 5d 00 8b 44 24 ?? 8a 54 14 ?? 32 da 88 5d 00 } //1
		$a_81_2 = {4d 77 56 56 52 6b 30 67 72 66 32 42 5a 71 54 69 58 4c 63 69 41 62 77 35 64 61 6b 76 } //1 MwVVRk0grf2BZqTiXLciAbw5dakv
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_81_2  & 1)*1) >=1
 
}