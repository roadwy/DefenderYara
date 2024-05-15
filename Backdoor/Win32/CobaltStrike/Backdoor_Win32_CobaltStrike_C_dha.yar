
rule Backdoor_Win32_CobaltStrike_C_dha{
	meta:
		description = "Backdoor:Win32/CobaltStrike.C!dha,SIGNATURE_TYPE_PEHSTR,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {81 7e 58 32 32 32 58 } //02 00 
		$a_01_1 = {70 00 61 00 79 00 6c 00 6f 00 61 00 64 00 2e 00 62 00 69 00 6e 00 } //01 00  payload.bin
		$a_01_2 = {57 69 72 65 73 68 61 72 6b } //01 00  Wireshark
		$a_01_3 = {54 6f 72 74 6f 69 73 65 53 56 4e } //00 00  TortoiseSVN
		$a_01_4 = {00 67 16 00 } //00 4a 
	condition:
		any of ($a_*)
 
}