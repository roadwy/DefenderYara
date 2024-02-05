
rule Trojan_Win32_TrickBotCrypt_GD_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 55 d4 0f b6 02 0f b6 4d db 33 c1 8b 55 d4 2b 55 08 0f b6 ca 81 e1 e0 00 00 00 33 c1 8b 55 d4 88 02 8b 45 d4 03 45 e4 89 45 d4 } //00 00 
	condition:
		any of ($a_*)
 
}