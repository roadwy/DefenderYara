
rule Trojan_Win32_Braduk_A_bit{
	meta:
		description = "Trojan:Win32/Braduk.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 6d 69 6e 65 72 55 52 4c } //01 00  main.minerURL
		$a_01_1 = {6d 61 69 6e 2e 77 61 74 63 68 4d 69 6e 65 72 } //01 00  main.watchMiner
		$a_01_2 = {2e 63 6f 6d 6d 61 6e 64 43 68 65 63 6b 45 78 70 6c 6f 69 74 65 64 } //01 00  .commandCheckExploited
		$a_01_3 = {2e 64 6f 77 6e 6c 6f 61 64 41 6e 64 52 75 6e } //01 00  .downloadAndRun
		$a_01_4 = {2e 77 61 74 63 68 52 65 67 69 73 74 72 79 53 74 61 72 74 75 70 } //00 00  .watchRegistryStartup
	condition:
		any of ($a_*)
 
}