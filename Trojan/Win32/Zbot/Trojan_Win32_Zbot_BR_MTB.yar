
rule Trojan_Win32_Zbot_BR_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 f7 29 35 90 02 04 03 d0 e8 90 02 04 2b f7 8b 45 ec 46 8b c1 4f 81 f9 c6 1c 42 4a 0f 85 90 00 } //5
		$a_01_1 = {33 d8 89 5d f8 03 7d fc 33 df 48 74 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}