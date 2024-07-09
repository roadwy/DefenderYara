
rule Ransom_Win32_PrincessLocker_A{
	meta:
		description = "Ransom:Win32/PrincessLocker.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {c6 45 fc 02 8d 45 ?? 83 7d ?? 10 0f 43 45 ?? 50 53 ff 15 ?? ?? ?? ?? 68 00 00 00 f0 6a 18 68 ?? ?? ?? ?? 6a 00 8b f8 68 ?? ?? ?? ?? ff d7 } //1
		$a_03_1 = {3a 00 5c 00 50 ff 15 ?? ?? ?? ?? 83 f8 03 74 09 83 f8 04 0f 85 ?? ?? 00 00 6a 00 6a 00 6a 00 6a 00 8d 45 e4 50 ff 15 ?? ?? ?? ?? 85 c0 0f 84 } //1
		$a_03_2 = {83 c3 1a 83 c0 1a 89 9d ?? ?? ff ff 89 85 ?? ?? ff ff 81 fb 46 9a 00 00 0f 82 ?? ?? ff ff 8b 85 ?? ?? ff ff 83 f8 08 72 13 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}