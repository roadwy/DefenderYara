
rule Trojan_Win32_Stealer_O_bit{
	meta:
		description = "Trojan:Win32/Stealer.O!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 75 c4 83 c6 04 8d 7d e8 a5 a5 a5 a5 8b 75 08 83 c6 04 8b 7d c4 83 c7 04 a5 a5 a5 a5 8b 7d 08 83 c7 04 8d 75 e8 a5 a5 a5 a5 8b 45 c4 8b 40 14 89 45 fc 8b 45 c4 8b 4d 08 8b 49 14 89 48 14 8b 45 08 8b 4d fc 89 48 14 8b 45 c4 8b 40 18 89 45 e4 8b 45 c4 8b 4d 08 8b 49 18 89 48 18 8b 45 08 8b 4d e4 89 48 18 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 73 63 74 } //00 00  VirtualProtsct
	condition:
		any of ($a_*)
 
}