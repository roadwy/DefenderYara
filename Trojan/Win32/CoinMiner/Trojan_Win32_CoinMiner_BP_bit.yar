
rule Trojan_Win32_CoinMiner_BP_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.BP!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {53 46 58 20 73 63 72 69 70 74 20 63 6f 6d 6d 61 6e 64 73 0d 0a 0d 0a 50 61 74 68 3d [0-10] 6d 69 6e 65 72 0d 0a 53 61 76 65 50 61 74 68 0d 0a 53 65 74 75 70 3d 22 [0-10] 6d 69 6e 65 72 5c [0-10] 2e 76 62 73 22 0d 0a 53 69 6c 65 6e 74 3d 31 } //1
		$a_01_1 = {72 65 67 20 61 64 64 20 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}