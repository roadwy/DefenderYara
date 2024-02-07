
rule TrojanDownloader_BAT_Downcoin_B{
	meta:
		description = "TrojanDownloader:BAT/Downcoin.B,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {66 00 69 00 6c 00 65 00 68 00 6f 00 73 00 74 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 66 00 69 00 6c 00 65 00 73 00 2f 00 32 00 35 00 2f 00 62 00 69 00 74 00 63 00 6f 00 69 00 6e 00 2d 00 6d 00 69 00 6e 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //0a 00  filehostonline.com/files/25/bitcoin-miner.exe
		$a_01_1 = {77 00 69 00 6e 00 6d 00 69 00 6e 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //01 00  winminer.exe
		$a_01_2 = {77 00 69 00 6e 00 64 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //01 00  windefender.exe
		$a_01_3 = {77 00 69 00 6e 00 73 00 72 00 76 00 2e 00 65 00 78 00 65 00 } //00 00  winsrv.exe
	condition:
		any of ($a_*)
 
}