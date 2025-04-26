
rule TrojanDownloader_BAT_Dedoal_B{
	meta:
		description = "TrojanDownloader:BAT/Dedoal.B,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_01_0 = {47 42 45 78 69 73 74 73 56 32 } //1 GBExistsV2
		$a_01_1 = {47 42 46 69 6c 65 45 78 69 73 74 73 } //1 GBFileExists
		$a_01_2 = {50 61 72 73 65 46 69 6c 65 4e 61 6d 65 } //1 ParseFileName
		$a_01_3 = {41 6e 74 69 76 69 72 75 73 49 6e 73 74 61 6c 6c 65 64 } //1 AntivirusInstalled
		$a_01_4 = {44 65 74 65 63 74 41 56 52 65 73 75 6c 74 } //1 DetectAVResult
		$a_01_5 = {50 6f 73 74 61 41 76 69 73 6f } //1 PostaAviso
		$a_01_6 = {43 72 69 61 41 6c 65 72 74 61 } //1 CriaAlerta
		$a_01_7 = {4d 61 6e 64 61 72 41 76 69 73 6f } //1 MandarAviso
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=7
 
}