
rule Trojan_Win32_TrickBotCrypt_DY_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.DY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 14 32 2a d0 a0 90 01 04 f6 e9 8b 4c 24 1c 02 d0 a0 90 01 04 2a d0 8b 44 24 10 8a 1c 08 32 da 88 1c 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}