
rule Trojan_Win32_Convagent_BAF_MTB{
	meta:
		description = "Trojan:Win32/Convagent.BAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 d8 89 d9 c1 e8 18 c1 e9 0c 31 c1 32 8e ?? ?? ?? ?? 0f b6 d1 8d 8c 24 90 90 00 00 00 e8 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Convagent_BAF_MTB_2{
	meta:
		description = "Trojan:Win32/Convagent.BAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 c2 0b c8 88 4d f4 8b 45 88 8b 08 33 4d ac 8b 55 90 89 0a 8b 45 d8 2b 45 ec 03 45 d4 03 45 f4 89 45 e0 8b 4d f8 3b 4d dc 77 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Convagent_BAF_MTB_3{
	meta:
		description = "Trojan:Win32/Convagent.BAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 30 00 00 ff 77 50 6a 00 ff 15 ?? ?? ?? ?? 8b d0 89 55 fc 85 d2 0f 84 ?? ?? ?? ?? 0f b7 4f 06 56 0f b7 77 14 83 c6 18 8d 04 89 03 f7 c1 e0 03 2b c3 03 c6 50 53 52 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}