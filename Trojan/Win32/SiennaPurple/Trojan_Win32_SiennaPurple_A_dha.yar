
rule Trojan_Win32_SiennaPurple_A_dha{
	meta:
		description = "Trojan:Win32/SiennaPurple.A!dha,SIGNATURE_TYPE_PEHSTR,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {5c 46 6f 72 4f 50 5c 61 74 74 61 63 6b 28 75 74 69 6c 73 29 5c 61 74 74 61 63 6b 20 74 6f 6f 6c 73 5c 42 61 63 6b 64 6f 6f 72 5c 70 6f 77 65 72 73 68 65 6c 6c 5c 62 74 6c 63 5f 43 5c 52 65 6c 65 61 73 65 5c 62 74 6c 63 5f 43 2e 70 64 62 } //01 00  \ForOP\attack(utils)\attack tools\Backdoor\powershell\btlc_C\Release\btlc_C.pdb
		$a_01_1 = {2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 33 38 31 39 30 37 34 37 35 31 37 34 39 37 38 39 31 35 33 38 34 31 34 36 36 30 38 31 } //01 00  ----------3819074751749789153841466081
		$a_01_2 = {0f be 02 83 e8 30 8b 4d 08 88 01 } //00 00 
	condition:
		any of ($a_*)
 
}