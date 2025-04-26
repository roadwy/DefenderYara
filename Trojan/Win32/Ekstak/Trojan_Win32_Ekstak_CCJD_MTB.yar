
rule Trojan_Win32_Ekstak_CCJD_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.CCJD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {53 55 56 57 ff 15 ?? ?? 4c 00 8b 5c 24 14 68 64 50 4c 00 53 a3 ?? ?? 4c 00 ff 15 ?? ?? 4c 00 85 c0 74 09 6a 00 e8 ?? ?? ?? ?? eb 05 e8 ?? ?? ?? ?? 8b 0d ?? ?? 4c 00 8b 2d ?? ?? 4c 00 6a 00 6a 00 6a ff 53 03 c8 } //5
		$a_03_1 = {83 ec 08 8d 44 24 00 56 33 f6 50 68 19 00 02 00 56 68 74 30 4c 00 68 00 00 00 80 ff 15 ?? ?? ?? ?? 85 c0 74 09 33 c0 5e } //5
		$a_03_2 = {55 8b ec 83 ec 10 53 56 57 68 ?? ?? 4c 00 e8 ?? ?? f5 ff 89 45 fc e9 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_03_2  & 1)*1) >=6
 
}