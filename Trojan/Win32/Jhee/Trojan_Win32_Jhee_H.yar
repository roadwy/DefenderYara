
rule Trojan_Win32_Jhee_H{
	meta:
		description = "Trojan:Win32/Jhee.H,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_00_1 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
		$a_03_2 = {74 5a 6a 00 57 8b 4d 0c 51 56 53 ff 15 ?? ?? ?? 10 85 c0 74 47 68 ?? ?? ?? 10 68 ?? ?? ?? 10 ff 15 ?? ?? ?? 10 50 ff 15 ?? ?? ?? 10 89 45 ?? 85 c0 74 29 6a 00 6a 00 56 50 6a 00 6a 00 53 ff 15 ?? ?? ?? 10 8b f8 89 7d ?? 85 ff 74 12 6a ff 57 ff 15 ?? ?? ?? 10 c6 45 ?? ?? eb 03 } //1
		$a_03_3 = {68 d0 07 00 00 ff d6 8d 54 24 08 52 57 e8 ?? ?? ?? ff 83 c4 08 85 c0 74 e7 5e } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}