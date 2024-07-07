
rule TrojanDownloader_Win32_Pilrurl_A{
	meta:
		description = "TrojanDownloader:Win32/Pilrurl.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_01_0 = {1b 04 00 04 78 ff 34 6c 78 ff f5 01 00 00 80 0a } //2
		$a_00_1 = {4b 00 56 00 4d 00 6f 00 6e 00 58 00 50 00 2e 00 6b 00 78 00 70 00 2c 00 4b 00 76 00 58 00 50 00 2e 00 6b 00 78 00 70 00 } //2 KVMonXP.kxp,KvXP.kxp
		$a_00_2 = {4b 00 41 00 56 00 33 00 32 00 2e 00 45 00 58 00 45 00 2c 00 4b 00 41 00 54 00 4d 00 61 00 69 00 6e 00 2e 00 45 00 58 00 45 00 } //2 KAV32.EXE,KATMain.EXE
		$a_00_3 = {5c 00 49 00 45 00 4c 00 4f 00 43 00 4b 00 2e 00 56 00 42 00 50 00 } //1 \IELOCK.VBP
		$a_00_4 = {53 00 74 00 61 00 72 00 74 00 20 00 50 00 61 00 67 00 65 00 } //1 Start Page
		$a_00_5 = {3a 00 70 00 72 00 75 00 72 00 6c 00 } //1 :prurl
		$a_01_6 = {54 65 72 6d 69 6e 61 74 65 50 72 6f 63 65 73 73 } //1 TerminateProcess
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1) >=8
 
}