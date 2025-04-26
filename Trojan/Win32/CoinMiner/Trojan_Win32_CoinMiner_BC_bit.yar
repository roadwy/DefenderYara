
rule Trojan_Win32_CoinMiner_BC_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.BC!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 76 63 68 6f 73 74 2e 65 78 65 20 69 6e 73 74 61 6c 6c 20 57 69 6e 64 6f 77 73 20 22 43 3a 5c 57 69 6e 64 6f 77 73 5c 63 73 72 73 73 2e 65 78 65 22 } //1 svchost.exe install Windows "C:\Windows\csrss.exe"
		$a_01_1 = {6b 61 73 79 61 6e 6f 66 66 } //1 kasyanoff
		$a_01_2 = {2d 2d 61 75 74 6f 2d 67 70 75 } //1 --auto-gpu
		$a_01_3 = {64 38 62 66 62 63 63 36 33 66 30 65 34 62 37 61 61 33 32 64 37 62 32 33 65 32 37 32 34 66 66 62 32 35 66 62 65 31 61 32 65 31 36 65 65 65 36 33 65 39 30 66 66 38 65 65 66 36 63 33 38 32 66 33 61 39 65 38 66 62 38 33 65 30 34 62 } //1 d8bfbcc63f0e4b7aa32d7b23e2724ffb25fbe1a2e16eee63e90ff8eef6c382f3a9e8fb83e04b
		$a_01_4 = {73 74 61 72 74 20 57 69 6e 64 6f 77 73 } //1 start Windows
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}