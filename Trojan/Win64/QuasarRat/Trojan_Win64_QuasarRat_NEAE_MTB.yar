
rule Trojan_Win64_QuasarRat_NEAE_MTB{
	meta:
		description = "Trojan:Win64/QuasarRat.NEAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 0c 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 73 70 6f 6f 66 65 72 2e 73 79 74 65 73 2e 6e 65 74 2f } //5 http://spoofer.sytes.net/
		$a_01_1 = {43 68 65 63 6b 69 6e 67 20 69 66 20 75 73 65 72 20 69 73 20 61 64 6d 69 6e 2e 2e 2e } //2 Checking if user is admin...
		$a_01_2 = {73 74 61 72 74 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 49 4d 45 } //2 start C:\Windows\System32\IME
		$a_01_3 = {53 74 61 72 74 69 6e 67 20 73 70 6f 6f 66 65 72 2e 2e 2e } //2 Starting spoofer...
		$a_01_4 = {52 65 67 69 73 74 72 79 20 65 6e 74 72 69 65 73 20 77 65 72 65 20 73 70 6f 6f 66 65 64 2e } //2 Registry entries were spoofed.
		$a_01_5 = {52 65 6d 6f 76 65 64 20 61 6e 79 20 74 72 61 63 65 20 66 69 6c 65 73 20 66 6f 75 6e 64 2e } //2 Removed any trace files found.
		$a_01_6 = {43 6f 6e 73 6f 6c 65 41 70 70 6c 69 63 61 74 69 6f 6e 2e 70 64 62 } //2 ConsoleApplication.pdb
		$a_01_7 = {44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 } //1 DisableAntiSpyware
		$a_01_8 = {44 69 73 61 62 6c 65 52 65 61 6c 74 69 6d 65 4d 6f 6e 69 74 6f 72 69 6e 67 } //1 DisableRealtimeMonitoring
		$a_01_9 = {44 69 73 61 62 6c 65 42 65 68 61 76 69 6f 72 4d 6f 6e 69 74 6f 72 69 6e 67 } //1 DisableBehaviorMonitoring
		$a_01_10 = {44 69 73 61 62 6c 65 53 63 61 6e 4f 6e 52 65 61 6c 74 69 6d 65 45 6e 61 62 6c 65 } //1 DisableScanOnRealtimeEnable
		$a_01_11 = {44 69 73 61 62 6c 65 4f 6e 41 63 63 65 73 73 50 72 6f 74 65 63 74 69 6f 6e } //1 DisableOnAccessProtection
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=22
 
}