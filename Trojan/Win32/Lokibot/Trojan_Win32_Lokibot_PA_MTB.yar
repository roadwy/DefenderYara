
rule Trojan_Win32_Lokibot_PA_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 03 00 00 14 00 "
		
	strings :
		$a_02_0 = {8b 45 08 03 45 90 01 01 73 05 e8 90 01 04 8a 00 88 45 90 01 01 8a 45 90 01 01 34 90 01 01 8b 55 08 03 55 90 01 01 73 05 e8 90 01 04 88 02 ff 45 90 01 01 81 7d 90 01 03 02 00 75 ce ff 65 08 90 00 } //01 00 
		$a_02_1 = {50 6a 40 68 90 01 02 02 00 8b 45 08 50 e8 90 00 } //01 00 
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}