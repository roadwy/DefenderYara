
rule Trojan_Win32_TrickBotCrypt_FP_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.FP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 04 0e 03 c2 33 d2 f7 35 90 01 04 8b 44 24 18 03 da 2b dd 8b 2d 90 01 04 03 dd 8a 14 0b 8a 18 32 da 8b 54 24 20 88 18 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}