
rule PWS_Win32_OnLineGames_MA_dll{
	meta:
		description = "PWS:Win32/OnLineGames.MA!dll,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {72 78 6a 68 2e 31 37 67 61 6d 65 2e 63 6f 6d } //1 rxjh.17game.com
		$a_01_1 = {7a 68 69 68 75 69 67 75 61 6e } //1 zhihuiguan
		$a_01_2 = {52 58 4a 48 5f 4b 49 43 4b 41 52 53 45 30 2e } //1 RXJH_KICKARSE0.
		$a_01_3 = {57 48 45 52 45 53 48 58 54 45 30 2e } //1 WHERESHXTE0.
		$a_01_4 = {44 6e 73 47 65 74 42 75 66 66 65 72 4c 65 6e 67 74 68 46 6f 72 53 74 72 69 6e 67 43 6f 70 79 } //1 DnsGetBufferLengthForStringCopy
		$a_01_5 = {44 6e 73 47 65 74 43 61 63 68 65 44 61 74 61 54 61 62 6c 65 } //1 DnsGetCacheDataTable
		$a_01_6 = {66 65 65 64 55 52 4c } //1 feedURL
		$a_01_7 = {59 42 5f 4f 6e 6c 69 6e 65 43 6c 69 65 6e 74 } //1 YB_OnlineClient
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}