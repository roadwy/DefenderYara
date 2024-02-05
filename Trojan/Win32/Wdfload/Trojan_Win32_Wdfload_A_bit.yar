
rule Trojan_Win32_Wdfload_A_bit{
	meta:
		description = "Trojan:Win32/Wdfload.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 08 8b 44 24 08 80 90 01 02 8a 90 02 06 32 c8 8b 44 24 08 88 90 02 06 ff 44 24 08 83 7c 24 08 90 01 01 72 90 00 } //01 00 
		$a_03_1 = {0f be 08 8d 52 01 90 01 02 81 c6 90 01 04 88 8d 90 01 04 8a 85 90 01 04 30 42 ff 8b 85 90 01 04 83 ef 01 75 d8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}