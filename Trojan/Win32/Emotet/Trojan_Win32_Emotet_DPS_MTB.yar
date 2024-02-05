
rule Trojan_Win32_Emotet_DPS_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b 4c 24 10 0f be 04 01 50 ff 74 24 90 01 01 e8 90 01 04 8b 54 24 90 01 01 59 59 8b 4c 24 10 88 04 11 90 09 04 00 8b 44 24 90 00 } //02 00 
		$a_02_1 = {8b 6c 24 14 8b 4c 24 90 01 01 8b 44 24 1c 0f be 14 29 52 50 e8 90 01 04 8b 4c 24 90 01 01 83 c4 08 88 04 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}