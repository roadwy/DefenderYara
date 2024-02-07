
rule Trojan_Win32_VidarStealer_RMA_MTB{
	meta:
		description = "Trojan:Win32/VidarStealer.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 08 00 00 0a 00 "
		
	strings :
		$a_81_0 = {74 76 7a 78 73 78 64 64 61 71 77 69 68 6f 70 6d 71 68 74 75 62 67 69 6a 72 62 } //0a 00  tvzxsxddaqwihopmqhtubgijrb
		$a_81_1 = {50 59 57 75 49 35 5c 36 44 4e 72 59 5c 74 45 71 4a 61 53 6b 5c 4f 4e 32 4b 39 54 68 4a 43 4c 6d } //01 00  PYWuI5\6DNrY\tEqJaSk\ON2K9ThJCLm
		$a_81_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00  VirtualAlloc
		$a_81_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_81_4 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //01 00  GetCurrentProcess
		$a_81_5 = {57 49 4e 4d 4d 2e 64 6c 6c } //01 00  WINMM.dll
		$a_81_6 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_81_7 = {47 65 74 53 74 61 72 74 75 70 49 6e 66 6f 57 } //00 00  GetStartupInfoW
	condition:
		any of ($a_*)
 
}