
rule Trojan_Win32_CoinMiner_RPQ_MTB{
	meta:
		description = "Trojan:Win32/CoinMiner.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_01_0 = {54 61 73 6b 6d 67 72 2e 65 78 65 } //1 Taskmgr.exe
		$a_01_1 = {53 74 6f 70 70 65 72 2d 6d 75 74 65 78 } //1 Stopper-mutex
		$a_01_2 = {6d 65 74 68 6f 64 2f 77 61 6c 6c 2e 67 65 74 2e 78 6d 6c } //1 method/wall.get.xml
		$a_01_3 = {52 61 75 6d 2d 77 69 74 68 2d 4d 65 } //1 Raum-with-Me
		$a_01_4 = {6d 69 6e 69 6e 67 5f 69 6e 66 6f } //1 mining_info
		$a_01_5 = {74 6f 6f 6c 73 2f 72 65 67 77 72 69 74 65 2e 72 61 75 6d 5f 65 6e 63 72 79 70 74 65 64 } //1 tools/regwrite.raum_encrypted
		$a_01_6 = {3c 65 6e 63 72 79 70 74 69 6f 6e 5f 6b 65 79 3e } //1 <encryption_key>
		$a_01_7 = {4e 6f 20 65 76 69 6c 20 68 65 72 65 2c 20 74 72 75 73 74 20 6d 65 } //1 No evil here, trust me
		$a_01_8 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_9 = {47 65 74 46 6f 72 65 67 72 6f 75 6e 64 57 69 6e 64 6f 77 } //1 GetForegroundWindow
		$a_01_10 = {4b 61 73 70 65 72 73 6b 79 } //1 Kaspersky
		$a_01_11 = {61 76 61 73 74 } //1 avast
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=12
 
}