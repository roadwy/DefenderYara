
rule Trojan_Win32_StealC_SZ_MTB{
	meta:
		description = "Trojan:Win32/StealC.SZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 14 38 83 ?? 0f 75 ?? 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8d 85 f0 ?? ff ff 50 8d 8d fc ?? ff ff 51 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_StealC_SZ_MTB_2{
	meta:
		description = "Trojan:Win32/StealC.SZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {4d 6f 6e 65 72 6f 5c 77 61 6c 6c 65 74 2e 6b 65 79 73 } //1 Monero\wallet.keys
		$a_01_1 = {70 61 73 73 77 6f 72 64 73 2e 74 78 74 } //1 passwords.txt
		$a_01_2 = {53 45 4c 45 43 54 20 74 61 72 67 65 74 5f 70 61 74 68 2c 20 74 61 62 5f 75 72 6c 20 66 72 6f 6d 20 64 6f 77 6e 6c 6f 61 64 73 } //1 SELECT target_path, tab_url from downloads
		$a_01_3 = {5c 42 72 61 76 65 57 61 6c 6c 65 74 5c 50 72 65 66 65 72 65 6e 63 65 73 } //1 \BraveWallet\Preferences
		$a_01_4 = {49 6e 76 6f 6b 65 2d 45 78 70 72 65 73 73 69 6f 6e 20 28 49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 20 2d 55 72 69 } //1 Invoke-Expression (Invoke-WebRequest -Uri
		$a_01_5 = {2d 55 73 65 42 61 73 69 63 50 61 72 73 69 6e 67 29 2e 43 6f 6e 74 65 6e 74 } //1 -UseBasicParsing).Content
		$a_01_6 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 } //1 powershell.exe
		$a_81_7 = {76 6d 63 68 65 63 6b } //1 vmcheck
		$a_81_8 = {61 76 67 68 6f 6f 6b 78 } //1 avghookx
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}