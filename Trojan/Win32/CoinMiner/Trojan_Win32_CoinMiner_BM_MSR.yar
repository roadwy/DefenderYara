
rule Trojan_Win32_CoinMiner_BM_MSR{
	meta:
		description = "Trojan:Win32/CoinMiner.BM!MSR,SIGNATURE_TYPE_PEHSTR,05 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {6c 6f 67 2e 62 6f 72 65 79 65 2e 63 6f 6d } //01 00  log.boreye.com
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 4e 65 74 77 6f 72 6b 50 6c 61 74 66 6f 72 6d 5c 4c 6f 63 61 74 69 6f 6e } //01 00  Software\Microsoft\Windows NT\CurrentVersion\NetworkPlatform\Location
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 68 6f 73 74 } //01 00  SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost
		$a_01_3 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 25 73 } //00 00  SYSTEM\CurrentControlSet\Services\%s
		$a_01_4 = {00 5d 04 00 } //00 9f 
	condition:
		any of ($a_*)
 
}