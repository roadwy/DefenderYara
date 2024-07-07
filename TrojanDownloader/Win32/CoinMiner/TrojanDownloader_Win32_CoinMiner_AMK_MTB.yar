
rule TrojanDownloader_Win32_CoinMiner_AMK_MTB{
	meta:
		description = "TrojanDownloader:Win32/CoinMiner.AMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,24 00 24 00 0c 00 00 "
		
	strings :
		$a_80_0 = {2e 62 6f 6f 74 } //.boot  3
		$a_80_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 57 } //URLDownloadToFileW  3
		$a_80_2 = {42 43 72 79 70 74 44 65 72 69 76 65 4b 65 79 50 42 4b 44 46 32 } //BCryptDeriveKeyPBKDF2  3
		$a_80_3 = {57 4c 53 6f 66 74 77 61 72 65 56 65 72 73 69 6f 6e } //WLSoftwareVersion  3
		$a_80_4 = {2f 73 68 6f 77 63 6f 64 65 32 } ///showcode2  3
		$a_80_5 = {2f 6c 6f 67 73 74 61 74 75 73 } ///logstatus  3
		$a_80_6 = {2f 62 75 67 63 68 65 63 6b 32 } ///bugcheck2  3
		$a_80_7 = {2f 73 6b 69 70 61 63 74 69 76 65 78 72 65 67 } ///skipactivexreg  3
		$a_80_8 = {53 6f 66 74 77 61 72 65 5c 57 4c 6b 74 } //Software\WLkt  3
		$a_80_9 = {2f 62 75 67 63 68 65 63 6b 66 75 6c 6c } ///bugcheckfull  3
		$a_80_10 = {2f 64 65 61 63 74 69 76 61 74 65 } ///deactivate  3
		$a_80_11 = {54 68 65 6d 69 64 61 } //Themida  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3+(#a_80_8  & 1)*3+(#a_80_9  & 1)*3+(#a_80_10  & 1)*3+(#a_80_11  & 1)*3) >=36
 
}