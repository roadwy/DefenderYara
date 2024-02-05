
rule Trojan_Win32_Lokibot_PD_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 06 8d 04 80 8b 55 90 01 01 8b 54 90 01 02 89 17 8b 55 90 01 01 8b 44 90 01 02 a3 90 01 04 8b 07 3b 05 90 01 04 73 16 a1 90 01 04 31 07 8b 07 31 05 90 01 04 a1 90 01 04 31 07 90 00 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}