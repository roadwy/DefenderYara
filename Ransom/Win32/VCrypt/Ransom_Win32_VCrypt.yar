
rule Ransom_Win32_VCrypt{
	meta:
		description = "Ransom:Win32/VCrypt,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 09 00 00 02 00 "
		
	strings :
		$a_01_0 = {5c 67 65 74 5f 6d 79 5f 66 69 6c 65 73 2e 74 78 74 } //02 00  \get_my_files.txt
		$a_01_1 = {2a 2a 2a 20 41 4c 4c 20 59 4f 55 52 20 57 4f 52 4b 20 41 4e 44 20 50 45 52 53 4f 4e 41 4c 20 46 49 4c 45 53 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 20 2a 2a 2a } //02 00  *** ALL YOUR WORK AND PERSONAL FILES HAVE BEEN ENCRYPTED ***
		$a_01_2 = {54 6f 20 64 65 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 20 79 6f 75 20 6e 65 65 64 20 74 6f 20 62 75 79 20 74 68 65 20 73 70 65 63 69 61 6c 20 73 6f 66 74 77 61 72 65 } //02 00  To decrypt your files you need to buy the special software
		$a_01_3 = {6a 7a 33 73 6e 63 76 6d 76 65 70 72 68 69 68 6b 2e 6f 6e 69 6f 6e 20 28 6e 65 65 64 20 54 6f 72 2d 62 72 6f 77 73 65 72 29 } //02 00  jz3sncvmveprhihk.onion (need Tor-browser)
		$a_01_4 = {6a 7a 33 73 6e 63 76 6d 76 65 70 72 68 69 68 6b 2e 6f 6e 69 6f 6e 2e 72 69 70 } //02 00  jz3sncvmveprhihk.onion.rip
		$a_01_5 = {6a 7a 33 73 6e 63 76 6d 76 65 70 72 68 69 68 6b 2e 6f 6e 69 6f 6e 2e 63 61 62 } //02 00  jz3sncvmveprhihk.onion.cab
		$a_01_6 = {6a 7a 33 73 6e 63 76 6d 76 65 70 72 68 69 68 6b 2e 68 69 64 64 65 6e 73 65 72 76 69 63 65 2e 6e 65 74 } //02 00  jz3sncvmveprhihk.hiddenservice.net
		$a_01_7 = {64 61 76 69 64 66 72 65 65 6d 6f 6e 32 40 61 6f 6c 2e 63 6f 6d } //02 00  davidfreemon2@aol.com
		$a_01_8 = {64 61 76 69 64 00 2e 64 61 76 69 64 00 00 } //00 00 
		$a_00_9 = {5d 04 00 00 e1 b0 } //03 80 
	condition:
		any of ($a_*)
 
}