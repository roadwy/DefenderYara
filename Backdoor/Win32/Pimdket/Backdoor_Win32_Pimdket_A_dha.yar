
rule Backdoor_Win32_Pimdket_A_dha{
	meta:
		description = "Backdoor:Win32/Pimdket.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {81 38 45 72 69 63 0f 85 } //01 00 
		$a_01_1 = {73 74 61 72 74 20 74 6f 20 65 78 65 63 75 74 65 20 73 68 65 6c 6c } //01 00  start to execute shell
		$a_03_2 = {80 bd 31 04 00 00 00 74 18 8d 4c 24 90 01 01 57 8d 85 2f 03 00 00 51 e8 90 01 02 00 00 8b 7c 24 90 01 01 83 c4 08 90 00 } //00 00 
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}