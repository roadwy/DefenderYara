
rule TrojanDownloader_Win32_Brbank_A{
	meta:
		description = "TrojanDownloader:Win32/Brbank.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {69 74 61 75 61 70 6c 69 63 61 74 69 76 6f 2e 65 78 65 } //1 itauaplicativo.exe
		$a_03_1 = {31 c0 39 c2 74 0a 80 b0 ?? ?? ?? ?? 08 40 eb } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}