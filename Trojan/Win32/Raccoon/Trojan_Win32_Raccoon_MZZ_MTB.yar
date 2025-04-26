
rule Trojan_Win32_Raccoon_MZZ_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.MZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c9 c1 ea 18 8b b4 8f ?? ?? ?? ?? 8b c8 03 74 97 48 8b 55 f4 c1 e9 08 0f b6 c9 33 b4 8f 48 08 00 00 0f b6 c8 03 b4 8f 48 0c 00 00 8b 4d 0c 33 34 0a 83 6d fc 01 8b 4d 08 89 34 0a 8b 4d 0c 8b 75 08 89 04 0a 75 } //5
		$a_01_1 = {8d 4f 44 89 44 32 04 8b 07 31 04 32 8b 45 f8 40 89 45 f8 3b 45 10 0f 82 68 ff ff ff } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}