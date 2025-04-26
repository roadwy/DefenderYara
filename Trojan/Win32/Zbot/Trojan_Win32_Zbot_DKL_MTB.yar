
rule Trojan_Win32_Zbot_DKL_MTB{
	meta:
		description = "Trojan:Win32/Zbot.DKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 05 00 00 "
		
	strings :
		$a_02_0 = {8b 38 03 fe 33 db b8 ?? ?? ?? ?? 2d 8d 8b ec 55 8b 0f 8b 55 ec 81 c2 ?? ?? ?? ?? 33 ca 23 c8 3b cb 0f 85 4e 0e 00 00 } //10
		$a_02_1 = {89 16 b9 8d 15 55 fc 81 f1 ?? ?? ?? ?? 03 f1 ba ?? ?? ?? ?? 81 f2 ?? ?? ?? ?? 03 da 81 c3 ?? ?? ?? ?? 89 5d a0 c1 c6 0a 89 b5 ?? ?? ?? ?? 5e 5b 5f c3 } //10
		$a_01_2 = {66 74 63 2e 65 78 65 } //1 ftc.exe
		$a_80_3 = {4b 72 61 6d 69 76 6f } //Kramivo  1
		$a_80_4 = {4a 6b 61 64 73 75 78 69 63 6e 69 } //Jkadsuxicni  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_01_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=23
 
}