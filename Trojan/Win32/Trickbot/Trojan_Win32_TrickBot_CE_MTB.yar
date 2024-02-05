
rule Trojan_Win32_TrickBot_CE_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 0a 6a 05 68 90 01 04 e8 90 01 04 68 90 01 04 68 90 01 04 e8 90 01 04 8a 4c 24 90 01 01 8b 84 24 90 01 04 02 d9 83 c4 30 8a 14 06 81 e3 ff 00 00 00 8a 4c 1c 90 01 01 32 d1 88 14 06 8b 84 24 90 01 04 46 3b f0 0f 8c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}