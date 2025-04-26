
rule TrojanDownloader_Win32_CoinMiner_QE_bit{
	meta:
		description = "TrojanDownloader:Win32/CoinMiner.QE!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 74 74 72 69 62 20 2b 68 } //1 attrib +h
		$a_01_1 = {53 43 48 54 41 53 4b 53 20 2f 43 72 65 61 74 65 20 2f 53 43 20 4d 49 4e 55 54 45 20 2f 4d 4f } //1 SCHTASKS /Create /SC MINUTE /MO
		$a_01_2 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 4e 6f 50 20 2d 4e 6f 6e 49 20 2d 57 20 48 69 64 64 65 6e 20 2d 45 78 65 63 20 42 79 70 61 73 73 20 49 45 58 20 28 4e 65 77 2d 4f 62 6a 65 63 74 20 53 79 73 74 65 6d 2e 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 powershell.exe -NoP -NonI -W Hidden -Exec Bypass IEX (New-Object System.Net.WebClient).DownloadFile
		$a_03_3 = {24 65 6e 76 3a 41 50 50 44 41 54 41 5c 75 70 64 61 74 65 5c [0-10] 2e 65 78 65 } //1
		$a_03_4 = {34 2e 70 72 6f 67 72 61 6d 2d 69 71 2e 63 6f 6d 2f 75 70 6c 6f 61 64 73 2f [0-20] 2e 6a 70 67 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}