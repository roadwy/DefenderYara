
rule Trojan_Win32_Qbot_KSP_MTB{
	meta:
		description = "Trojan:Win32/Qbot.KSP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_00_0 = {8a 4c 24 12 8a d1 8a c4 c0 e0 04 46 c0 ea 02 0a d0 c0 e1 06 0a 4c 24 13 88 16 } //2
		$a_02_1 = {8b f6 33 3d 90 01 04 8b cf b8 04 00 00 00 03 c1 83 e8 04 a3 90 01 04 a1 90 01 04 8b 0d 90 01 04 89 08 90 00 } //2
		$a_02_2 = {0f b6 c3 03 f8 81 e7 ff 00 00 00 81 3d 64 2b 4f 00 81 0c 00 00 75 90 09 0c 00 a1 90 01 04 0f b6 b8 90 00 } //1
		$a_02_3 = {30 04 1f 4f 79 90 09 05 00 e8 90 00 } //1
	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*2+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=2
 
}