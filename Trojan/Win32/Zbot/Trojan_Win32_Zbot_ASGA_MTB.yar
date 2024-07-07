
rule Trojan_Win32_Zbot_ASGA_MTB{
	meta:
		description = "Trojan:Win32/Zbot.ASGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {b7 ff 84 0f 0b f8 55 8b 2d 78 5a 3f e8 8c 62 53 5a e9 8d 88 1e 5a db ff 76 fb 5d c3 90 2b 1b 39 03 07 7b b9 0b 23 63 7a 89 8d } //2
		$a_01_1 = {17 44 e8 6b 0e 4c 8b 45 d0 35 41 db dd fd 6f 7b 01 2d cd db 74 f0 89 85 5c 19 e9 3d 10 93 0b c3 57 b3 fc db 7e b8 d8 ac c8 13 14 34 39 57 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}