
rule Worm_Win32_Dorkbot_BA_bit{
	meta:
		description = "Worm:Win32/Dorkbot.BA!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 61 6d 70 6c 65 20 73 74 72 69 6e 67 20 68 61 73 20 62 65 65 6e 20 66 75 63 6b 65 64 } //2 sample string has been fucked
		$a_03_1 = {8b 45 e0 03 45 f0 0f b6 08 0f be 55 b3 0f af 55 dc 0f be 45 b3 8b 75 dc 2b f0 33 d6 03 ca 8b 15 90 01 04 03 55 ac 88 0a 90 00 } //1
		$a_01_2 = {8b fa 85 c0 c1 ff 02 c1 e7 02 8b f9 c0 fe 04 c0 e6 04 87 df d0 ef d0 e7 f7 d2 ff d0 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}