
rule Ransom_Win32_Kraken_F{
	meta:
		description = "Ransom:Win32/Kraken.F,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {5f 72 65 61 64 6d 65 5f 79 6f 75 5f 77 73 5f 68 61 63 6b 65 64 5f 2e 74 78 74 } //1 _readme_you_ws_hacked_.txt
		$a_01_1 = {64 6f 20 6e 6f 74 20 63 72 79 70 74 2f 64 65 6c 65 74 65 2f 63 6c 65 61 6e 75 70 20 61 6e 79 74 68 69 6e 67 2c 20 6a 75 73 74 20 64 72 6f 70 20 6e 6f 74 65 20 65 61 63 68 20 66 6f 75 6e 64 20 66 6f 6c 64 65 72 2e } //1 do not crypt/delete/cleanup anything, just drop note each found folder.
		$a_01_2 = {74 75 72 6e 20 6f 66 66 20 70 6c 61 74 66 6f 72 6d 20 73 70 65 63 69 66 79 20 65 78 74 65 6e 73 69 6f 6e 73 20 6c 69 73 74 20 61 6e 64 20 65 6e 63 72 79 70 74 20 61 6e 79 20 66 6f 75 6e 64 20 66 69 6c 65 73 20 6f 6e 20 74 68 65 20 64 69 73 6b } //1 turn off platform specify extensions list and encrypt any found files on the disk
		$a_01_3 = {54 68 72 65 61 64 73 20 63 6f 75 6e 74 3a 20 62 69 6e 2e 65 78 65 20 2d 74 68 72 65 61 64 73 20 31 } //1 Threads count: bin.exe -threads 1
		$a_01_4 = {64 6f 20 6e 6f 74 20 70 72 6f 63 65 73 73 20 64 72 69 76 65 73 3b 20 62 69 6e 2e 65 78 65 20 2d 6e 6f 64 72 69 76 65 73 } //1 do not process drives; bin.exe -nodrives
		$a_01_5 = {64 6f 20 6e 6f 74 20 70 72 6f 63 65 73 73 20 68 79 70 65 72 76 } //1 do not process hyperv
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}