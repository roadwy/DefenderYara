
rule Trojan_Win32_Cloptern_A_dha{
	meta:
		description = "Trojan:Win32/Cloptern.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {83 7d ec 00 74 47 6a 01 6a 00 6a 00 8d 55 } //01 00 
		$a_01_1 = {61 69 72 70 6c 75 67 69 6e 2a 2e 64 61 74 } //01 00 
		$a_01_2 = {2c 73 74 61 72 74 31 20 2f 65 78 63 } //00 00 
	condition:
		any of ($a_*)
 
}