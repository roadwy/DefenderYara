
rule TrojanDownloader_Win32_Adodb_A{
	meta:
		description = "TrojanDownloader:Win32/Adodb.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 00 61 00 79 00 70 00 74 00 68 00 20 00 3d 00 } //01 00  paypth =
		$a_01_1 = {6c 00 6e 00 6b 00 6e 00 6d 00 65 00 20 00 3d 00 } //01 00  lnknme =
		$a_01_2 = {53 00 76 00 72 00 20 00 3d 00 20 00 22 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 } //01 00  Svr = "http://
		$a_01_3 = {30 00 30 00 30 00 30 00 32 00 20 00 70 00 65 00 65 00 6c 00 53 00 2e 00 74 00 70 00 69 00 72 00 63 00 73 00 57 00 } //01 00  00002 peelS.tpircsW
		$a_01_4 = {73 00 62 00 76 00 2e 00 73 00 79 00 72 00 74 00 } //00 00  sbv.syrt
	condition:
		any of ($a_*)
 
}