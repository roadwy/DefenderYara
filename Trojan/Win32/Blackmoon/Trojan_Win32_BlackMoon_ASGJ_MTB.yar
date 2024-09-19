
rule Trojan_Win32_BlackMoon_ASGJ_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.ASGJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {89 45 fc 89 65 f8 68 00 00 00 00 68 00 00 00 00 ff 75 08 ff 75 fc 68 00 00 00 00 68 00 00 00 00 33 c0 ff 15 ?? ?? ?? 10 ?? ?? 39 65 f8 74 17 68 5c 00 00 00 68 76 51 01 04 68 06 00 00 00 e8 } //1
		$a_03_1 = {89 65 f4 68 64 00 00 00 33 c0 ff 15 ?? ?? ?? 10 ?? ?? 39 65 f4 74 17 68 e1 0a 00 00 68 97 5b 01 04 68 06 00 00 00 e8 ?? ?? 00 00 83 c4 0c eb } //1
		$a_01_2 = {47 6c 6f 62 61 6c 5c 76 63 70 6b 67 73 72 76 6d 67 72 } //1 Global\vcpkgsrvmgr
		$a_01_3 = {62 6c 61 63 6b 6d 6f 6f 6e } //1 blackmoon
		$a_01_4 = {70 70 78 68 5f 63 31 64 6a 63 } //1 ppxh_c1djc
		$a_01_5 = {43 72 65 61 74 65 4d 75 74 65 78 57 } //1 CreateMutexW
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}