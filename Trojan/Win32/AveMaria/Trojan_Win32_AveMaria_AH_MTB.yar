
rule Trojan_Win32_AveMaria_AH_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 bd 64 ff ff ff 89 95 58 ff ff ff 81 bd 5c ff ff ff 00 00 00 01 74 2a 8b 95 7c ff ff ff 03 95 5c ff ff ff 0f be 02 8b 8d 58 ff ff ff 0f be 54 0d 84 33 c2 8b 8d 7c ff ff ff 03 8d 5c ff ff ff 88 01 eb } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win32_AveMaria_AH_MTB_2{
	meta:
		description = "Trojan:Win32/AveMaria.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 "
		
	strings :
		$a_80_0 = {46 6c 6f 77 65 72 50 6f 77 65 72 } //FlowerPower  3
		$a_80_1 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //CreateToolhelp32Snapshot  3
		$a_80_2 = {53 48 47 65 74 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 50 61 74 68 41 } //SHGetSpecialFolderPathA  3
		$a_80_3 = {47 65 74 54 6f 6b 65 6e 49 6e 66 6f 72 6d 61 74 69 6f 6e } //GetTokenInformation  3
		$a_80_4 = {49 73 57 6f 77 36 34 50 72 6f 63 65 73 73 } //IsWow64Process  3
		$a_80_5 = {61 70 45 71 75 61 6c 53 69 64 } //apEqualSid  3
		$a_80_6 = {45 78 74 54 65 78 74 4f 75 74 41 } //ExtTextOutA  3
		$a_80_7 = {43 6c 69 65 6e 74 54 6f 53 63 72 65 65 6e } //ClientToScreen  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3) >=24
 
}