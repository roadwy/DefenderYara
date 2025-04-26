
rule TrojanDownloader_Win32_Misfox_A{
	meta:
		description = "TrojanDownloader:Win32/Misfox.A,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 06 00 00 "
		
	strings :
		$a_01_0 = {eb 09 0f be c9 c1 c0 07 33 c1 42 8a 0a 84 c9 75 f1 } //10
		$a_01_1 = {8a 01 3c 61 7c 15 3c 7a 7f 11 0f be c0 83 e8 54 6a 1a 99 5f f7 ff 80 c2 61 eb 17 3c 41 7c 15 3c 5a 7f 11 0f be c0 83 e8 34 6a 1a 99 5f f7 ff 80 c2 41 88 11 41 80 39 00 75 c6 } //10
		$a_00_2 = {59 3a 5c 00 58 3a 5c 00 5a 3a 5c 00 48 3a 5c 00 47 3a 5c 00 46 3a 5c 00 45 3a 5c 00 44 3a 5c 00 43 3a 5c 00 } //1 㩙\㩘\㩚\㩈\㩇\㩆\㩅\㩄\㩃\
		$a_02_3 = {68 74 74 70 3a 2f 2f [0-03] 2e [0-03] 2e [0-03] 2e [0-03] 2f } //1
		$a_00_4 = {62 69 6e 67 2e 63 6f 6d } //1 bing.com
		$a_00_5 = {4e 4a 42 23 } //1 NJB#
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=23
 
}