
rule TrojanSpy_Win32_Banker_AJP{
	meta:
		description = "TrojanSpy:Win32/Banker.AJP,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {94 14 85 c9 74 0c 39 08 75 08 89 cf 8b 41 fc 4a eb 02 31 c0 8b 4c 94 14 85 c9 74 0b } //1
		$a_03_1 = {35 ae ca 7b c3 ff 25 ?? ?? ?? ?? 8b c0 53 33 db 6a 00 e8 ee ff ff ff 83 f8 07 75 1c } //1
		$a_03_2 = {8b f0 0f b6 c3 8b 6c 87 04 eb ?? 8b 6d 00 85 ed 74 ?? 3b 75 04 75 } //1
		$a_03_3 = {eb 27 46 8b c3 34 01 84 c0 74 1b 8d 45 f4 8b 55 fc 0f b6 54 32 ff e8 ?? ?? ff ff 8b 55 f4 8d 45 f8 e8 ?? ?? ff ff 80 f3 01 } //1
		$a_01_4 = {99 f7 7d d4 8b da 3b 75 e0 7d 03 46 eb 05 be 01 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}