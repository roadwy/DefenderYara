
rule TrojanDownloader_Win16_Loguluk_A{
	meta:
		description = "TrojanDownloader:Win16/Loguluk.A,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {22 47 45 54 22 2c 20 22 68 74 74 70 3a 2f 2f 6c 6f 67 69 6e 2e 75 6c 2d 74 73 2e 75 6b 2f 70 72 69 76 61 63 79 2f 30 30 2d 50 52 56 2d 32 30 31 36 90 02 02 50 72 69 76 61 63 79 25 32 30 61 6e 64 25 32 30 4c 65 67 61 6c 25 32 30 41 67 72 65 65 6d 65 6e 74 2e 64 6f 63 22 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}