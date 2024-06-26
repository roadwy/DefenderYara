
rule Trojan_Win32_Guloader_BH_MTB{
	meta:
		description = "Trojan:Win32/Guloader.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 e9 04 81 34 0b 90 01 04 90 02 06 83 f9 00 75 90 01 01 53 eb 90 00 } //01 00 
		$a_01_1 = {50 89 e0 83 c4 06 ff 28 e8 90 01 01 ff ff ff c3 } //01 00 
		$a_03_2 = {85 db 64 8b 1d c0 00 00 00 83 fb 00 74 90 01 01 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Guloader_BH_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 42 65 66 72 69 65 6c 73 65 72 73 5c 61 6c 6c 65 72 69 6e 64 65 72 73 74 65 5c 70 65 6c 6f 62 61 74 69 64 } //01 00  Software\Befrielsers\allerinderste\pelobatid
		$a_01_1 = {53 69 6c 75 72 6f 69 64 73 25 5c 50 6f 6c 75 70 68 6c 6f 69 73 62 6f 69 63 5c 53 74 61 74 75 72 65 5c 4e 69 63 6b 6c 61 76 73 5c 44 69 70 68 65 6e 6f 78 79 6c 61 74 65 2e 4e 61 65 } //01 00  Siluroids%\Poluphloisboic\Stature\Nicklavs\Diphenoxylate.Nae
		$a_01_2 = {73 70 65 64 61 6c 73 6b 5c 52 75 73 73 65 6e 73 5c 42 69 6f 70 68 6f 74 6f 70 68 6f 6e 65 2e 64 6c 6c } //01 00  spedalsk\Russens\Biophotophone.dll
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4e 6f 6e 72 65 67 61 72 64 61 6e 63 65 } //01 00  Software\Nonregardance
		$a_01_4 = {53 6b 6e 68 65 64 73 73 61 6e 73 65 6e 2e 41 64 65 } //00 00  Sknhedssansen.Ade
	condition:
		any of ($a_*)
 
}