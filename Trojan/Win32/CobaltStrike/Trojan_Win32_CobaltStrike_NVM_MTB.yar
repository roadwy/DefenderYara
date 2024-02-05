
rule Trojan_Win32_CobaltStrike_NVM_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.NVM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8b 4d 0c 8a 11 88 10 8b 45 08 83 c0 01 89 45 08 8b 4d 0c 83 c1 01 89 4d 0c eb cd } //01 00 
		$a_01_1 = {6a 40 68 00 10 00 00 68 40 fc 00 00 6a 00 ff 15 } //01 00 
		$a_01_2 = {05 00 01 00 00 89 45 e8 8b 4d e4 03 4d ec 8a 55 e8 88 11 eb b3 } //00 00 
	condition:
		any of ($a_*)
 
}