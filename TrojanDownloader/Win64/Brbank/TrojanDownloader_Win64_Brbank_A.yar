
rule TrojanDownloader_Win64_Brbank_A{
	meta:
		description = "TrojanDownloader:Win64/Brbank.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 74 61 75 61 70 6c 69 63 61 74 69 76 6f 2e 65 78 65 } //02 00  itauaplicativo.exe
		$a_01_1 = {31 c0 49 39 c1 76 09 80 34 02 08 48 ff c0 eb } //00 00 
		$a_00_2 = {7e 15 } //00 00  ᕾ
	condition:
		any of ($a_*)
 
}