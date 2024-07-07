
rule Trojan_Win32_Zbot_FL_MTB{
	meta:
		description = "Trojan:Win32/Zbot.FL.MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 55 e0 8b 45 f4 01 d0 0f b6 08 8b 45 f4 83 e0 1f 0f b6 44 05 8e 89 c3 8b 55 e4 8b 45 f4 01 d0 31 d9 89 ca 88 10 83 45 f4 01 81 7d f4 ff af 00 00 76 cd } //10
		$a_01_1 = {c7 44 24 10 00 00 00 00 8d 45 88 89 44 24 0c c7 44 24 08 00 b0 00 00 8b 45 e4 89 44 24 04 8b 45 ec 89 04 24 e8 cb 00 00 00 83 ec 14 8b 45 ec 89 04 24 } //10
		$a_80_2 = {6d 61 6c 2e 65 78 65 } //mal.exe  1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_80_2  & 1)*1) >=21
 
}