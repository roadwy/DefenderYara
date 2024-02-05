
rule Trojan_Win32_TrickBotCrypt_NA_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 4d ec 3b 90 02 04 8b 90 02 02 0f 90 02 02 0f 90 02 03 33 90 01 01 8b 90 02 02 2b 90 02 02 0f 90 02 02 83 90 02 02 33 90 01 01 8b 90 02 02 88 90 01 01 8b 90 02 02 03 90 02 02 89 90 02 02 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}