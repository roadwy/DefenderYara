
rule Trojan_Win64_Blackout_A_MTB{
	meta:
		description = "Trojan:Win64/Blackout.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {42 6c 61 63 6b 6f 75 74 2e 65 78 65 20 2d 70 20 3c 70 72 6f 63 65 73 73 5f 69 64 3e } //02 00  Blackout.exe -p <process_id>
		$a_01_1 = {54 65 72 6d 69 6e 61 74 69 6e 67 20 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 } //02 00  Terminating Windows Defender
		$a_01_2 = {5c 00 5c 00 2e 00 5c 00 42 00 6c 00 61 00 63 00 6b 00 6f 00 75 00 74 00 } //02 00  \\.\Blackout
		$a_01_3 = {42 6c 61 63 6b 6f 75 74 2e 73 79 73 } //00 00  Blackout.sys
	condition:
		any of ($a_*)
 
}