
rule Trojan_Win32_Lokibot_PC_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {5a 80 34 01 b2 41 39 d1 75 90 01 01 05 90 01 02 00 00 ff e0 90 0a 80 00 b8 90 01 03 00 50 e8 90 01 03 ff b8 90 01 03 00 31 c9 68 90 01 02 00 00 90 00 } //01 00 
		$a_02_1 = {53 51 8b d8 68 90 01 03 00 68 90 01 03 00 e8 90 01 04 50 e8 90 01 04 54 6a 40 68 90 01 02 00 00 53 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}