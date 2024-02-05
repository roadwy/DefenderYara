
rule Trojan_Win32_TrickBotCrypt_FF_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.FF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4d fc 8a 82 90 01 04 03 ca f6 d0 3b cf 73 90 01 01 8a d1 2a d3 32 11 32 d0 88 11 03 ce 3b cf 72 90 01 01 8b 55 f8 42 89 55 f8 3b d6 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}