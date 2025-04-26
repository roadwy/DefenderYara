
rule Trojan_Win32_Ekstak_ASGE_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASGE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {83 ec 0c 56 57 ff 15 ?? ?? ?? 00 8b f0 8d 44 24 08 33 ff 50 68 19 00 02 00 57 68 ?? ?? ?? 00 68 00 00 00 80 ff 15 ?? ?? ?? 00 85 c0 74 } //2
		$a_03_1 = {8b ec 83 ec 0c 53 56 57 68 ?? ?? ?? 00 e8 ?? ?? ?? ff 89 45 fc e9 } //2
		$a_03_2 = {51 6a 01 ff 15 ?? ?? ?? 00 68 ?? ?? ?? 00 a3 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 68 ?? ?? ?? 00 50 ff 15 ?? ?? ?? 00 8a 44 24 00 59 c3 } //2
		$a_03_3 = {55 8b ec 83 ec 0c 53 56 57 e8 ?? ?? ?? ff 0f be c0 89 45 fc e9 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2) >=4
 
}