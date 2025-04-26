
rule Trojan_Win32_Trickbot_MST_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.MST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_02_0 = {8a 14 3e 8b c6 83 e0 1f 8a 0c 18 8b 44 24 ?? 32 d1 88 14 3e 46 3b f0 } //1
		$a_00_1 = {8b c1 33 d2 bd 25 00 00 00 f7 f5 8a 04 1a 8a 14 31 32 d0 88 14 31 41 3b cf } //1
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 4e 75 6d 61 } //1 VirtualAllocExNuma
		$a_80_3 = {44 48 74 6d 6c 45 64 69 74 44 65 6d 6f 2e 65 78 65 } //DHtmlEditDemo.exe  1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_80_3  & 1)*1) >=3
 
}