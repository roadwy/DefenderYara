
rule Trojan_Win32_Zbot_BO_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 f7 33 c0 50 c1 c8 07 31 04 24 ac 84 c0 75 } //2
		$a_01_1 = {03 d7 c1 e1 02 03 d1 8b 12 03 d7 89 13 8b 4d 08 03 cf 89 4d 04 5b e9 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}