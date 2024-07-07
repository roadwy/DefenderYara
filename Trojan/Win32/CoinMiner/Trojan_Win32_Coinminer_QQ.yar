
rule Trojan_Win32_Coinminer_QQ{
	meta:
		description = "Trojan:Win32/Coinminer.QQ,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 62 00 6c 00 6f 00 63 00 6b 00 63 00 68 00 61 00 69 00 6e 00 2e 00 69 00 6e 00 66 00 6f 00 2f 00 61 00 64 00 64 00 72 00 65 00 73 00 73 00 2f 00 } //3 http://blockchain.info/address/
		$a_01_1 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //3 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {53 79 73 74 65 6d 20 2f 76 20 45 6e 61 62 6c 65 4c 55 41 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 30 20 2f 66 } //1 System /v EnableLUA /t REG_DWORD /d 0 /f
		$a_01_3 = {70 6f 77 65 72 63 66 67 2e 65 78 65 20 2d 68 20 6f 66 66 } //1 powercfg.exe -h off
		$a_01_4 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 73 65 74 20 6f 70 6d 6f 64 65 20 6d 6f 64 65 3d 64 69 73 61 62 6c 65 } //1 netsh firewall set opmode mode=disable
		$a_01_5 = {6e 65 74 73 68 20 61 64 76 66 69 72 65 77 61 6c 6c 20 73 65 74 20 61 6c 6c 70 72 6f 66 69 6c 65 73 20 73 74 61 74 65 20 6f 66 66 } //1 netsh advfirewall set allprofiles state off
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}