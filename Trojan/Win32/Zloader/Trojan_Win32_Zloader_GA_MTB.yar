
rule Trojan_Win32_Zloader_GA_MTB{
	meta:
		description = "Trojan:Win32/Zloader.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_02_0 = {8a 0c 32 88 0c 38 8b 55 ?? 83 c2 ?? 89 55 [0-0f] 5f 5e 8b e5 5d c3 90 0a 32 00 03 45 ?? 8b } //5
		$a_02_1 = {03 01 8b 55 ?? 89 02 8b 45 ?? 8b 08 83 e9 ?? 8b 55 ?? 89 0a 8b e5 5d c3 } //5
		$a_02_2 = {8b c2 c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 11 90 0a 32 00 90 17 04 01 01 01 01 31 32 30 33 } //10
	condition:
		((#a_02_0  & 1)*5+(#a_02_1  & 1)*5+(#a_02_2  & 1)*10) >=15
 
}