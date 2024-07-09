
rule Trojan_Win32_Emotet_DGH_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DGH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_02_0 = {81 e1 ff 00 00 00 03 c1 b9 74 59 01 00 99 f7 f9 8a 4d 00 8a 9c 14 ?? ?? ?? ?? 32 d9 } //1
		$a_81_1 = {35 66 4a 43 54 50 4d 4a 45 61 77 42 30 56 32 5a 47 36 35 4c 65 39 64 63 45 70 42 69 75 49 6b 58 61 6f 36 69 7a 6c 55 } //1 5fJCTPMJEawB0V2ZG65Le9dcEpBiuIkXao6izlU
		$a_02_2 = {0f b6 94 0d ?? ?? ?? ?? 03 c2 99 f7 bd ?? ?? ?? ?? 0f b6 84 15 90 1b 00 0f b6 8d ?? ?? ?? ?? 33 c8 88 8d 90 1b 03 68 ?? ?? ?? ?? e8 } //1
		$a_81_3 = {74 73 6e 51 4d 57 44 73 30 62 58 51 78 4b 6b 58 73 36 68 49 47 61 76 4f 50 53 71 43 59 79 30 47 59 37 4e 47 65 } //1 tsnQMWDs0bXQxKkXs6hIGavOPSqCYy0GY7NGe
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_02_2  & 1)*1+(#a_81_3  & 1)*1) >=1
 
}