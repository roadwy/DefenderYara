
rule Trojan_Win32_ClipBanker_BA_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_81_0 = {42 43 48 5f 50 32 50 4b 48 5f 43 61 73 68 41 64 64 72 } //1 BCH_P2PKH_CashAddr
		$a_81_1 = {42 54 43 5f 42 45 43 48 33 32 } //1 BTC_BECH32
		$a_81_2 = {56 45 52 54 43 4f 49 4e } //1 VERTCOIN
		$a_81_3 = {4e 41 4d 45 43 4f 49 4e } //1 NAMECOIN
		$a_81_4 = {47 65 74 53 69 6d 69 6c 61 72 41 64 64 72 65 73 73 } //1 GetSimilarAddress
		$a_81_5 = {57 72 69 74 65 41 6c 6c 42 79 74 65 73 } //1 WriteAllBytes
		$a_81_6 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //1 DownloadString
		$a_81_7 = {53 54 45 41 4d 5f 55 52 4c } //1 STEAM_URL
		$a_81_8 = {50 72 6f 63 65 73 73 54 68 72 65 61 64 43 6f 6c 6c 65 63 74 69 6f 6e } //1 ProcessThreadCollection
		$a_81_9 = {42 6c 6f 63 6b 43 43 57 } //1 BlockCCW
		$a_81_10 = {43 6c 69 70 62 6f 61 72 64 } //1 Clipboard
		$a_81_11 = {53 79 73 74 65 6d 2e 54 65 78 74 2e 52 65 67 75 6c 61 72 45 78 70 72 65 73 73 69 6f 6e 73 } //1 System.Text.RegularExpressions
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=12
 
}