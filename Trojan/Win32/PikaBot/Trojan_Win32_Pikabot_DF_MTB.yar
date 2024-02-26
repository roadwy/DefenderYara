
rule Trojan_Win32_Pikabot_DF_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 e8 8b 55 d8 01 02 8b 45 cc 03 45 ac 2d f2 5f 00 00 03 45 e8 8b 55 d8 31 02 83 45 e8 04 83 45 d8 04 8b 45 e8 3b 45 d4 } //00 00 
	condition:
		any of ($a_*)
 
}