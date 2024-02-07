
rule Trojan_Win32_TurtleLoaderEnc_A_dha{
	meta:
		description = "Trojan:Win32/TurtleLoaderEnc.A!dha,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {40 5b 2a 5d 20 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 3a } //01 00  @[*] WriteProcessMemory:
		$a_01_1 = {40 5b 2a 5d 20 53 6c 65 65 70 69 6e 67 20 74 6f 20 65 76 61 64 65 20 69 6e 20 6d 65 6d 6f 72 79 20 73 63 61 6e 6e 65 72 73 } //01 00  @[*] Sleeping to evade in memory scanners
		$a_01_2 = {40 20 75 73 69 6e 67 20 70 61 73 73 77 6f 72 64 3a } //00 00  @ using password:
	condition:
		any of ($a_*)
 
}