
rule Trojan_Win32_CobaltStrike_MA_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {ff 77 04 ff d6 59 85 c0 59 0f 84 90 01 04 68 90 01 04 ff 77 04 ff d6 59 85 c0 59 0f 84 90 01 04 68 90 01 04 ff 77 04 ff d6 59 85 c0 59 0f 84 90 01 04 68 90 01 04 ff 77 04 ff d6 59 85 c0 59 0f 84 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CobaltStrike_MA_MTB_2{
	meta:
		description = "Trojan:Win32/CobaltStrike.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 03 00 "
		
	strings :
		$a_01_0 = {34 00 33 00 2e 00 31 00 33 00 38 00 2e 00 33 00 30 00 2e 00 37 00 36 00 } //03 00  43.138.30.76
		$a_01_1 = {2f 00 6c 00 6f 00 67 00 67 00 69 00 6e 00 67 00 2e 00 62 00 69 00 6e 00 } //02 00  /logging.bin
		$a_01_2 = {83 bc 24 88 00 00 00 08 8d 4c 24 74 6a 00 0f 43 4c 24 78 6a 50 51 50 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CobaltStrike_MA_MTB_3{
	meta:
		description = "Trojan:Win32/CobaltStrike.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 4a 01 89 08 8b 4c 90 90 90 02 01 89 ca c1 ea 90 02 01 23 90 90 90 02 02 00 00 31 ca 89 d0 c1 e0 90 02 01 25 90 02 04 31 d0 89 c1 c1 e1 90 02 01 81 e1 90 02 04 31 c1 89 c8 c1 e8 90 02 01 31 c8 90 00 } //01 00 
		$a_01_1 = {62 72 6f 6b 65 6e 20 70 69 70 65 } //01 00  broken pipe
		$a_01_2 = {63 6f 6e 6e 65 63 74 69 6f 6e 20 61 62 6f 72 74 65 64 } //01 00  connection aborted
		$a_01_3 = {6f 77 6e 65 72 20 64 65 61 64 } //00 00  owner dead
	condition:
		any of ($a_*)
 
}