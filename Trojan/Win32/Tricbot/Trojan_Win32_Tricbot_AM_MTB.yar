
rule Trojan_Win32_Tricbot_AM_MTB{
	meta:
		description = "Trojan:Win32/Tricbot.AM!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {56 6a 00 8b f8 ff 55 fc 8b f0 57 89 75 fc ff 55 f8 6a 00 6a 40 68 00 30 00 00 56 6a 00 8b f8 ff d3 50 ff 55 f4 8b 5d fc 8b f0 85 db 74 0f 8b ce 2b fe 8b d3 8a 04 0f 88 01 41 4a 75 f7 8b 55 f0 53 56 e8 1c fb fe ff 59 59 ff d6 5f 5e 33 c0 5b 8b e5 5d c2 10 00 } //1
		$a_01_1 = {33 d2 8d 47 01 b9 2e 1c 00 00 f7 f1 8b fa 33 d2 8a 8c 3d c8 e3 ff ff 0f b6 c1 03 c6 be 2e 1c 00 00 f7 f6 8b f2 8a 84 35 c8 e3 ff ff 88 84 3d c8 e3 ff ff 88 8c 35 c8 e3 ff ff 0f b6 84 3d c8 e3 ff ff 0f b6 c9 03 c1 b9 2e 1c 00 00 99 f7 f9 8b 45 fc 8a 8c 15 c8 e3 ff ff 30 08 40 89 45 fc 4b 75 9e 8b 45 08 5f 5e 5b eb 02 33 c0 8b e5 5d c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}