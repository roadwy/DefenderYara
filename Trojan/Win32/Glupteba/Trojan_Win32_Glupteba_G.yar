
rule Trojan_Win32_Glupteba_G{
	meta:
		description = "Trojan:Win32/Glupteba.G,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 00 73 00 73 00 5c 00 63 00 73 00 72 00 73 00 73 00 2e 00 65 00 78 00 65 00 } //01 00  rss\csrss.exe
		$a_01_1 = {66 61 69 6c 65 64 20 74 6f 20 77 72 69 74 65 20 61 6e 20 69 6e 6a 65 63 74 6f 72 20 66 69 6c 65 } //01 00  failed to write an injector file
		$a_01_2 = {61 70 70 6c 69 63 61 74 69 6f 6e 2f 72 65 73 69 6c 69 65 6e 63 65 2f 62 6c 6f 63 6b 63 68 61 69 6e 63 6f 6d 2e 66 69 6e 64 4c 61 74 65 73 74 54 72 61 6e 73 61 63 74 69 6f 6e 44 61 74 61 } //01 00  application/resilience/blockchaincom.findLatestTransactionData
		$a_01_3 = {57 69 6e 6d 6f 6e 46 53 21 57 69 6e 6d 6f 6e 46 53 49 6e 73 74 61 6e 63 65 53 65 74 75 70 3a 20 45 6e 74 65 72 65 64 } //01 00  WinmonFS!WinmonFSInstanceSetup: Entered
		$a_01_4 = {62 69 74 63 6f 69 6e 33 6e 71 79 33 64 62 37 63 2e 6f 6e 69 6f 6e } //00 00  bitcoin3nqy3db7c.onion
	condition:
		any of ($a_*)
 
}