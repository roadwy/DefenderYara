
rule TrojanSpy_Win32_Ursnif_HT{
	meta:
		description = "TrojanSpy:Win32/Ursnif.HT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 45 08 8d 47 01 0f b6 f8 8d 76 01 8a 8f ?? ?? ?? ?? 0f b6 c1 03 c2 0f b6 d0 8a 82 90 1b 00 88 8a 90 1b 00 88 87 90 1b 00 0f b6 8a 90 1b 00 0f b6 c0 03 c8 0f b6 c1 8b 4d 08 0f b6 80 90 1b 00 32 44 31 ff 88 46 ff 83 eb 01 75 b2 } //1
		$a_01_1 = {64 62 67 2e 74 78 74 00 64 6c 6c 2e 62 69 6e 00 43 72 65 61 74 65 46 69 6c 65 41 20 65 72 72 6f 72 3a } //1
		$a_01_2 = {4d 65 6d 6f 72 79 43 61 6c 6c 45 6e 74 72 79 50 6f 69 6e 74 20 2d 3e 20 25 64 } //1 MemoryCallEntryPoint -> %d
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}