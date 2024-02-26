
rule Trojan_Win32_CoinMiner_MAI_MTB{
	meta:
		description = "Trojan:Win32/CoinMiner.MAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 6f 61 64 73 74 72 69 6e 67 28 67 61 6d 65 3a 48 74 74 70 47 65 74 28 22 68 74 74 70 73 3a 2f 2f 63 64 6e 2e 77 65 61 72 65 64 65 76 73 2e 6e 65 74 2f 73 63 72 69 70 74 73 2f 46 6c 79 2e 74 78 74 22 29 29 28 29 } //01 00  loadstring(game:HttpGet("https://cdn.wearedevs.net/scripts/Fly.txt"))()
		$a_01_1 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //01 00  IsProcessorFeaturePresent
		$a_01_2 = {51 75 65 72 79 50 65 72 66 6f 72 6d 61 6e 63 65 43 6f 75 6e 74 65 72 } //01 00  QueryPerformanceCounter
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //00 00  IsDebuggerPresent
	condition:
		any of ($a_*)
 
}