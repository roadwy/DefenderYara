
rule Trojan_Win32_CoinMiner_QE_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.QE!bit,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 06 00 00 "
		
	strings :
		$a_01_0 = {00 72 79 62 61 69 6b 6f 6c 62 61 73 61 2e 62 69 74 00 } //10
		$a_01_1 = {43 68 65 63 6b 4d 69 6e 65 72 } //1 CheckMiner
		$a_01_2 = {42 61 64 50 72 6f 63 65 73 73 } //1 BadProcess
		$a_01_3 = {50 72 6f 63 65 73 73 48 61 63 6b 65 72 2e 65 78 65 } //1 ProcessHacker.exe
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_5 = {2d 2d 63 70 75 2d 70 72 69 6f 72 69 74 79 3d 30 20 2d 2d 64 6f 6e 61 74 65 2d 6c 65 76 65 6c 3d 31 20 2d 6f 20 7b 50 4f 4f 4c 5f 41 44 44 52 45 53 53 7d 3a 7b 50 4f 4f 4c 5f 50 4f 52 54 7d } //1 --cpu-priority=0 --donate-level=1 -o {POOL_ADDRESS}:{POOL_PORT}
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=13
 
}