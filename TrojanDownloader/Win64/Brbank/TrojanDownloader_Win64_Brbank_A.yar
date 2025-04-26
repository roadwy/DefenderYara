
rule TrojanDownloader_Win64_Brbank_A{
	meta:
		description = "TrojanDownloader:Win64/Brbank.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {69 74 61 75 61 70 6c 69 63 61 74 69 76 6f 2e 65 78 65 } //1 itauaplicativo.exe
		$a_01_1 = {31 c0 49 39 c1 76 09 80 34 02 08 48 ff c0 eb } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}