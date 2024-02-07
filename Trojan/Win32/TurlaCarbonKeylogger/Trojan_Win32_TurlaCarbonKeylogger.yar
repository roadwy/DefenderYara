
rule Trojan_Win32_TurlaCarbonKeylogger{
	meta:
		description = "Trojan:Win32/TurlaCarbonKeylogger,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {5b 43 54 52 4c 2b 42 52 45 41 4b 20 50 52 4f 43 45 53 53 49 4e 47 5d } //01 00  [CTRL+BREAK PROCESSING]
		$a_01_1 = {5b 49 4d 45 20 4a 55 4e 4a 41 20 4d 4f 44 45 5d } //01 00  [IME JUNJA MODE]
		$a_01_2 = {46 61 69 6c 65 64 20 74 6f 20 63 72 65 61 74 65 64 20 70 72 6f 63 65 73 73 20 77 69 74 68 20 64 75 70 6c 69 63 61 74 65 64 20 74 6f 6b 65 6e 2e 20 45 72 72 6f 72 20 63 6f 64 65 3a 20 } //01 00  Failed to created process with duplicated token. Error code: 
		$a_01_3 = {53 65 74 20 68 6f 6f 6b 73 } //01 00  Set hooks
		$a_01_4 = {45 72 72 6f 72 20 67 65 74 74 69 6e 67 20 74 65 6d 70 20 70 61 74 68 3a } //00 00  Error getting temp path:
	condition:
		any of ($a_*)
 
}