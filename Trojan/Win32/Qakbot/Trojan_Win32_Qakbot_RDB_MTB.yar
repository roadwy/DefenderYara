
rule Trojan_Win32_Qakbot_RDB_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b d1 8b 4d fc 2b d7 8b c7 83 e0 7f 8a 04 18 32 04 0f 88 04 3a 47 83 ee 01 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_RDB_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 6b 63 73 31 31 68 5f 63 65 72 74 69 66 69 63 61 74 65 5f 64 65 63 72 79 70 74 } //01 00 
		$a_01_1 = {6b 6b 63 73 31 31 68 5f 61 64 64 50 72 6f 76 69 64 65 72 } //01 00 
		$a_01_2 = {6b 6b 63 73 31 31 68 5f 74 65 72 6d 69 6e 61 74 65 } //01 00 
		$a_01_3 = {6b 6b 63 73 31 31 68 5f 6f 70 65 6e 73 73 6c 5f 63 72 65 61 74 65 53 65 73 73 69 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}