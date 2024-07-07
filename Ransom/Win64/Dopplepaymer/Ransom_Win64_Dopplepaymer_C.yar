
rule Ransom_Win64_Dopplepaymer_C{
	meta:
		description = "Ransom:Win64/Dopplepaymer.C,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {20 00 2d 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 } //1  -Command 
		$a_00_1 = {2e 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 46 00 69 00 6c 00 65 00 28 00 27 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 65 00 6c 00 74 00 72 00 61 00 64 00 65 00 2e 00 72 00 6f 00 2f 00 6c 00 75 00 63 00 72 00 75 00 } //1 .DownloadFile('http://eltrade.ro/lucru
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}