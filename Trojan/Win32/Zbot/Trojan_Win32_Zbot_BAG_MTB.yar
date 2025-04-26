
rule Trojan_Win32_Zbot_BAG_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 c6 fe 83 ee ff 29 de 89 f3 6a 00 8f 01 01 31 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Zbot_BAG_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.BAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {40 90 48 90 90 90 a1 70 50 40 00 30 10 ba 74 50 40 00 ff 0a b8 70 50 40 00 ff 00 eb } //2
		$a_01_1 = {b9 1a 00 00 56 0f a2 0f 31 89 c6 0f a2 0f 31 29 f0 89 45 f4 5e 81 7d f4 00 01 00 00 7f } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule Trojan_Win32_Zbot_BAG_MTB_3{
	meta:
		description = "Trojan:Win32/Zbot.BAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c2 33 d2 b9 00 01 00 00 f7 f1 89 95 e8 fb ff ff 8b 95 e8 fb ff ff 8a 84 15 e4 fa ff ff 88 85 c0 f7 ff ff 8b 0d [0-04] 03 8d d0 f8 ff ff 0f be 11 0f be 85 c0 f7 ff ff 33 d0 8b 0d [0-04] 03 8d d0 f8 ff ff 88 11 e9 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}