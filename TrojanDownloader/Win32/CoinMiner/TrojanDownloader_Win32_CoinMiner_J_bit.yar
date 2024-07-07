
rule TrojanDownloader_Win32_CoinMiner_J_bit{
	meta:
		description = "TrojanDownloader:Win32/CoinMiner.J!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 68 61 74 61 6d 69 2e 75 73 2e 74 6f 2f 74 63 } //1 http://whatami.us.to/tc
		$a_01_1 = {6f 70 74 69 6f 6e 73 00 63 66 69 6c 65 00 63 63 61 72 67 73 } //1 灯楴湯s晣汩e捣牡獧
		$a_01_2 = {00 36 36 36 41 6e 6f 74 68 65 72 50 61 73 73 77 6f 72 64 36 36 36 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}