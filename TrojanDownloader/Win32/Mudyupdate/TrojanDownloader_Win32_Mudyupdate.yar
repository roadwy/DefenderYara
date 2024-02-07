
rule TrojanDownloader_Win32_Mudyupdate{
	meta:
		description = "TrojanDownloader:Win32/Mudyupdate,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 4d 00 57 00 50 00 5c 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 65 00 64 00 5c 00 53 00 74 00 61 00 72 00 74 00 2e 00 42 00 2e 00 31 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //01 00  \MWP\Processed\Start.B.1\Project1.vbp
		$a_01_1 = {65 00 78 00 65 00 2e 00 72 00 65 00 72 00 6f 00 6c 00 70 00 78 00 45 00 } //01 00  exe.rerolpxE
		$a_01_2 = {5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 20 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 20 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 5c 00 77 00 64 00 6d 00 2e 00 65 00 78 00 65 00 } //01 00  \Window Desktop Manager\wdm.exe
		$a_01_3 = {4d 00 53 00 58 00 4d 00 4c 00 32 00 2e 00 58 00 4d 00 4c 00 48 00 54 00 54 00 50 00 } //01 00  MSXML2.XMLHTTP
		$a_01_4 = {61 00 74 00 61 00 44 00 70 00 70 00 41 00 } //00 00  ataDppA
	condition:
		any of ($a_*)
 
}