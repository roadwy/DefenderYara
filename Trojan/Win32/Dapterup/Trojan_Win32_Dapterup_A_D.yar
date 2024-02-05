
rule Trojan_Win32_Dapterup_A_D{
	meta:
		description = "Trojan:Win32/Dapterup.A!D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 45 3a 3a 49 6e 73 74 61 6c 6c 43 65 72 74 28 29 3a } //02 00 
		$a_01_1 = {25 64 2f 25 64 2f 25 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 00 5b 25 73 5d 3a 5b 25 73 5d 3a 5b 25 69 5d 3a 5b 25 73 5d 3a 5b 25 73 5d 3a 5b 25 69 5d } //00 00 
		$a_00_2 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}