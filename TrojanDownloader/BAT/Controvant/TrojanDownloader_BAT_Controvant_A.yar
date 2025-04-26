
rule TrojanDownloader_BAT_Controvant_A{
	meta:
		description = "TrojanDownloader:BAT/Controvant.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 00 48 00 52 00 30 00 63 00 44 00 6f 00 76 00 4c 00 33 00 42 00 68 00 63 00 33 00 52 00 6c 00 59 00 6d 00 6c 00 75 00 4c 00 6d 00 4e 00 76 00 62 00 53 00 39 00 79 00 59 00 58 00 63 00 75 00 63 00 47 00 68 00 77 00 50 00 } //1 aHR0cDovL3Bhc3RlYmluLmNvbS9yYXcucGhwP
		$a_01_1 = {59 00 6f 00 75 00 72 00 20 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 20 00 6e 00 6f 00 74 00 20 00 66 00 6f 00 75 00 6e 00 64 00 20 00 6f 00 66 00 20 00 76 00 69 00 72 00 75 00 73 00 } //1 Your computer not found of virus
		$a_01_2 = {41 6e 74 69 76 69 72 75 73 20 32 30 31 35 2e 65 78 65 } //1 Antivirus 2015.exe
		$a_01_3 = {5c 48 61 74 20 4d 61 73 74 33 72 } //1 \Hat Mast3r
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}