
rule Trojan_Win64_StackedOats_A_dha{
	meta:
		description = "Trojan:Win64/StackedOats.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 07 00 00 "
		
	strings :
		$a_01_0 = {5b 2d 5d 20 44 65 62 75 67 41 63 74 69 76 65 50 72 6f 63 65 73 73 20 66 61 69 6c 65 64 3a 20 25 6c 75 } //1 [-] DebugActiveProcess failed: %lu
		$a_01_1 = {5b 2d 5d 20 4f 72 69 67 69 6e 20 42 79 74 65 73 20 52 65 61 64 20 66 61 69 6c 65 64 } //1 [-] Origin Bytes Read failed
		$a_01_2 = {5b 2d 5d 20 46 61 69 6c 65 64 20 74 6f 20 49 6e 73 65 72 74 20 42 72 65 61 6b 70 6f 69 6e 74 } //1 [-] Failed to Insert Breakpoint
		$a_01_3 = {5b 2b 5d 20 4d 6f 6e 69 74 6f 72 69 6e 67 20 50 6f 77 65 72 20 53 74 61 74 75 73 20 2e 2e 2e 20 } //1 [+] Monitoring Power Status ... 
		$a_01_4 = {53 68 75 74 64 6f 77 6e 43 6f 6e 66 69 72 6d 61 74 69 6f 6e } //1 ShutdownConfirmation
		$a_01_5 = {53 68 75 74 64 6f 77 6e 20 6f 72 20 52 65 73 74 61 72 74 21 21 21 21 21 } //1 Shutdown or Restart!!!!!
		$a_01_6 = {5b 2b 5d 20 46 6f 75 6e 64 20 6d 65 6d 63 70 79 20 69 6e 20 49 41 54 21 20 41 64 64 72 65 73 73 3a 20 30 78 25 70 } //1 [+] Found memcpy in IAT! Address: 0x%p
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=3
 
}