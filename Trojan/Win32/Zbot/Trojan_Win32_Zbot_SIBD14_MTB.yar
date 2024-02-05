
rule Trojan_Win32_Zbot_SIBD14_MTB{
	meta:
		description = "Trojan:Win32/Zbot.SIBD14!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 07 83 c7 90 01 01 8b f7 8b de 03 f8 90 18 8b d7 4a 2b c8 83 e9 90 01 01 52 ba 90 01 04 89 0a 89 7a 90 01 01 5a 8a 07 8a 26 02 25 90 01 04 32 c4 90 18 88 07 3b f2 74 90 01 01 46 47 49 75 90 01 01 eb 90 01 01 8b f3 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}