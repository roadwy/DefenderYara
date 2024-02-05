
rule Trojan_Win32_Zbot_CJ_MTB{
	meta:
		description = "Trojan:Win32/Zbot.CJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 d9 41 f7 e1 89 85 50 ff ff ff 33 85 58 ff ff ff 8b 95 54 ff ff ff 89 02 } //01 00 
		$a_01_1 = {8b 45 f8 8d 1c 03 31 f0 01 45 fc 09 f6 74 0c } //00 00 
	condition:
		any of ($a_*)
 
}