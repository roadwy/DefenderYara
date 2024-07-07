
rule TrojanDownloader_Win32_BrobanDel_A{
	meta:
		description = "TrojanDownloader:Win32/BrobanDel.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {75 67 67 63 3a 2f 2f } //1 uggc://
		$a_01_1 = {67 6f 6f 67 6c 65 61 70 69 73 2e 63 6f 6d } //1 googleapis.com
		$a_01_2 = {36 41 37 31 37 35 36 35 37 32 37 39 32 45 36 41 37 33 } //1 6A71756572792E6A73
		$a_01_3 = {36 39 37 34 36 31 32 45 36 41 37 33 } //1 6974612E6A73
		$a_01_4 = {62 69 74 2e 6c 79 2f } //1 bit.ly/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_Win32_BrobanDel_A_2{
	meta:
		description = "TrojanDownloader:Win32/BrobanDel.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {5c 6e 75 6d 62 65 72 63 68 61 6e 67 65 72 66 69 72 65 66 6f 78 2e 78 70 69 } //1 \numberchangerfirefox.xpi
		$a_01_1 = {36 44 37 33 37 38 32 45 36 35 37 38 36 35 } //1 6D73782E657865
		$a_00_2 = {53 65 75 20 63 6f 6d 70 75 74 61 64 6f 72 20 65 73 74 } //1 Seu computador est
		$a_00_3 = {75 73 65 72 5f 70 72 65 66 28 22 65 78 74 65 6e 73 69 6f 6e 73 2e 61 75 74 6f 44 69 73 61 62 6c 65 53 63 6f 70 65 73 22 2c 20 30 29 3b } //1 user_pref("extensions.autoDisableScopes", 0);
		$a_01_4 = {36 33 36 46 36 44 36 44 36 35 36 45 37 34 37 33 32 45 36 41 37 33 } //1 636F6D6D656E74732E6A73
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}