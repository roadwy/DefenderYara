
rule Trojan_Win32_TrickBotCrypt_DM_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.DM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 1c 32 2a d8 0f b6 05 90 01 04 b2 03 f6 ea 8b 55 90 01 01 02 d8 02 1d 90 01 04 8b 45 90 01 01 30 1c 10 40 89 45 90 01 01 3b 45 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}