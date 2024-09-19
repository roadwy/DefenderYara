
rule Trojan_Win32_Convagent_AGH_MTB{
	meta:
		description = "Trojan:Win32/Convagent.AGH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {8b d6 d1 ea 03 c2 33 d2 a3 ?? ?? ?? 00 83 e0 07 8a d1 68 ?? ?? ?? 00 0f af c2 03 f0 89 35 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 85 c0 89 07 5e } //2
		$a_03_1 = {55 8b ec 83 ec 10 53 56 57 68 ?? ?? ?? 00 e8 ?? ?? ?? ff 83 c4 04 e9 } //2
		$a_01_2 = {57 8d 0c 85 00 00 00 00 6a 00 0b ca 89 4c 24 08 df 6c 24 08 } //1
		$a_03_3 = {32 c8 8b 15 ?? ?? ?? 00 88 0d ?? ?? ?? 00 8a 0d ?? ?? ?? 00 80 c9 0c 53 c0 e9 02 81 e1 ff 00 00 00 52 89 4c 24 08 db 44 24 08 dc 3d } //3
		$a_03_4 = {83 ca 02 2b da 8b 15 ?? ?? ?? 00 89 1d ?? ?? ?? 00 33 db 8a 1d ?? ?? ?? 00 83 ca 01 0f af d3 33 ca 68 ?? ?? ?? 00 50 89 0d } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_03_3  & 1)*3+(#a_03_4  & 1)*2) >=5
 
}