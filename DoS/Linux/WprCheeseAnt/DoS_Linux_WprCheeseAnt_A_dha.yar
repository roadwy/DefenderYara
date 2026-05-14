
rule DoS_Linux_WprCheeseAnt_A_dha{
	meta:
		description = "DoS:Linux/WprCheeseAnt.A!dha,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 0d 00 00 "
		
	strings :
		$a_01_0 = {5b 2a 5d 20 53 74 61 72 74 69 6e 67 20 73 63 61 6e 20 77 69 74 68 20 } //1 [*] Starting scan with 
		$a_01_1 = {5b 2a 5d 20 52 6f 6f 74 73 20 74 6f 20 73 63 61 6e 3a 20 } //1 [*] Roots to scan: 
		$a_01_2 = {5b 3d 5d 20 53 63 61 6e 20 63 6f 6d 70 6c 65 74 65 20 69 6e 20 } //1 [=] Scan complete in 
		$a_01_3 = {5b 3d 5d 20 44 69 72 65 63 74 6f 72 69 65 73 20 74 72 61 76 65 72 73 65 64 3a 20 } //1 [=] Directories traversed: 
		$a_01_4 = {5b 3d 5d 20 46 69 6c 65 73 20 66 6f 75 6e 64 3a 20 } //1 [=] Files found: 
		$a_01_5 = {5b 3d 5d 20 46 69 6c 65 73 20 73 63 61 6e 6e 65 64 3a 20 } //1 [=] Files scanned: 
		$a_01_6 = {5b 3d 5d 20 46 69 6c 65 73 20 66 61 69 6c 65 64 3a 20 } //1 [=] Files failed: 
		$a_01_7 = {5b 2a 5d 20 54 72 61 76 65 72 73 61 6c 20 63 6f 6d 70 6c 65 74 65 2e 20 44 72 61 69 6e 69 6e 67 20 77 6f 72 6b 20 71 75 65 75 65 2e 2e 2e } //1 [*] Traversal complete. Draining work queue...
		$a_01_8 = {5b 21 5d 20 4e 6f 20 64 69 73 6b 73 20 66 6f 75 6e 64 2e } //1 [!] No disks found.
		$a_01_9 = {5b 44 49 53 4b 5d 3a 20 } //1 [DISK]: 
		$a_01_10 = {5b 2a 5d 20 53 6c 65 65 70 69 6e 67 20 66 6f 72 20 } //1 [*] Sleeping for 
		$a_01_11 = {20 73 65 63 6f 6e 64 73 2e 2e 2e } //1  seconds...
		$a_01_12 = {5b 2a 5d 20 45 6e 75 6d 65 72 61 74 69 6e 67 20 73 79 73 74 65 6d 20 64 69 73 6b 73 2e 2e 2e } //1 [*] Enumerating system disks...
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=5
 
}