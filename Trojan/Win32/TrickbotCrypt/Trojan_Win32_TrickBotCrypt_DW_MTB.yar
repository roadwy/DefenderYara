
rule Trojan_Win32_TrickBotCrypt_DW_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.DW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 04 0e 03 c2 33 d2 f7 35 90 01 04 a0 90 01 04 8a 14 0a 02 d0 8b 44 24 90 01 01 8a 1c 28 32 da 88 1c 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}