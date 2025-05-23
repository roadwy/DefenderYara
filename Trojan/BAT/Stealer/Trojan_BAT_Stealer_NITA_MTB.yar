
rule Trojan_BAT_Stealer_NITA_MTB{
	meta:
		description = "Trojan:BAT/Stealer.NITA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {02 8e 69 8d 03 00 00 01 0a 16 0b 2b 13 06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69 32 e7 06 2a } //2
		$a_01_1 = {47 65 74 43 6c 69 70 62 6f 61 72 64 54 65 78 74 } //1 GetClipboardText
		$a_01_2 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 GetClipboardData
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}
rule Trojan_BAT_Stealer_NITA_MTB_2{
	meta:
		description = "Trojan:BAT/Stealer.NITA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_01_0 = {44 65 63 72 79 70 74 42 72 6f 77 73 65 72 73 } //2 DecryptBrowsers
		$a_01_1 = {47 65 74 50 72 6f 63 65 73 73 65 73 42 79 4e 61 6d 65 } //2 GetProcessesByName
		$a_00_2 = {4d 00 6f 00 6e 00 65 00 72 00 6f 00 } //2 Monero
		$a_00_3 = {4c 00 69 00 74 00 65 00 63 00 6f 00 69 00 6e 00 43 00 6f 00 72 00 65 00 } //2 LitecoinCore
		$a_00_4 = {45 00 74 00 68 00 65 00 72 00 65 00 75 00 6d 00 } //1 Ethereum
		$a_00_5 = {50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 73 00 } //1 Passwords
		$a_01_6 = {67 65 74 5f 53 61 6e 64 42 6f 78 69 65 } //1 get_SandBoxie
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1) >=10
 
}