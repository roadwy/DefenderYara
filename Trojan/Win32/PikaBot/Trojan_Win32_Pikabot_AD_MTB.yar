
rule Trojan_Win32_Pikabot_AD_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 02 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_01_1 = {8a 84 3d f8 fe ff ff 88 8c 3d f8 fe ff ff 88 84 35 f8 fe ff ff 0f b6 8c 3d f8 fe ff ff 0f b6 c0 03 c8 0f b6 c1 8a 84 05 f8 fe ff ff 32 04 13 88 02 42 83 6d fc 01 75 } //100
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*100) >=101
 
}