
rule Trojan_Win32_TrickBotCrypt_GW_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.GW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 04 0f 88 04 0e 88 1c 0f 0f b6 04 0e 0f b6 d3 03 c2 33 d2 bb 90 01 04 f7 f3 8b 45 90 01 01 40 89 45 90 01 01 0f b6 1c 0a 8b 55 90 01 01 30 5c 10 90 01 01 3b 45 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}