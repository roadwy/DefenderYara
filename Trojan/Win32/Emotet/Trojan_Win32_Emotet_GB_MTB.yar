
rule Trojan_Win32_Emotet_GB_MTB{
	meta:
		description = "Trojan:Win32/Emotet.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b c8 03 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 2b c8 2b 0d ?? ?? ?? ?? 8b 45 08 0f b6 0c 08 8b 45 0c 0f b6 14 10 33 d1 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 8b 35 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Emotet_GB_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {68 17 14 78 72 89 [0-03] e8 [0-04] 68 db 49 35 93 89 [0-03] e8 [0-04] 68 ce 08 01 4e 89 [0-03] e8 [0-04] 68 ab 5e c3 4d 8b ?? e8 [0-04] 68 94 24 8e 94 89 [0-03] e8 [0-04] 68 a3 ca 26 af 8b ?? e8 [0-04] 68 a7 91 44 c9 8b ?? e8 } //1
		$a_02_1 = {33 c4 89 44 [0-19] f3 ?? 68 15 5b 04 71 [0-02] e8 [0-04] 68 20 e6 3c 0b 8b ?? e8 [0-04] 68 73 e1 88 9f 8b ?? e8 [0-04] 68 20 f6 3c 14 8b ?? e8 } //1
		$a_02_2 = {51 52 6a 00 6a 01 6a 00 50 ff [0-03] 5f f7 d8 5e 1b c0 23 [0-03] 5d 5b 83 c4 ?? c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}