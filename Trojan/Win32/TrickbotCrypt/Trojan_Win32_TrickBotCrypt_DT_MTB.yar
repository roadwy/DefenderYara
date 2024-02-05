
rule Trojan_Win32_TrickBotCrypt_DT_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.DT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 08 8b 55 90 01 01 8b 02 8b 55 90 01 01 8b 75 90 01 01 8a 0c 0a 32 0c 06 8b 55 90 01 01 8b 02 8b 55 90 01 01 88 0c 02 e9 90 09 03 00 8b 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}