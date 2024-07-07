
rule TrojanDownloader_BAT_Lenwadu_A_bit{
	meta:
		description = "TrojanDownloader:BAT/Lenwadu.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 75 00 2e 00 6c 00 65 00 77 00 64 00 2e 00 73 00 65 00 2f 00 } //2 https://u.lewd.se/
		$a_01_1 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 44 00 61 00 74 00 61 00 } //1 DownloadData
		$a_01_2 = {73 00 63 00 76 00 68 00 6f 00 73 00 74 00 } //1 scvhost
		$a_01_3 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 76 00 32 00 2e 00 30 00 2e 00 35 00 30 00 37 00 32 00 37 00 5c 00 } //1 C:\Windows\Microsoft.NET\Framework\v2.0.50727\
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}