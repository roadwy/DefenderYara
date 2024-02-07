
rule Trojan_BAT_Bladabindi_AM_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 61 69 66 69 6c 65 6d 6f 69 31 } //01 00  taifilemoi1
		$a_01_1 = {55 70 64 61 74 61 2e 65 78 65 } //01 00  Updata.exe
		$a_01_2 = {63 00 68 00 65 00 63 00 6b 00 2e 00 74 00 78 00 74 00 } //01 00  check.txt
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //01 00  DownloadFile
		$a_01_4 = {74 61 69 6d 75 74 69 } //01 00  taimuti
		$a_01_5 = {67 65 74 5f 4b 68 61 6b 69 } //00 00  get_Khaki
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Bladabindi_AM_MTB_2{
	meta:
		description = "Trojan:BAT/Bladabindi.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {fa 25 33 00 16 00 00 01 00 00 00 2a 00 00 00 0c 00 00 00 2b 00 00 00 36 00 00 00 32 00 00 00 10 } //02 00 
		$a_01_1 = {52 75 66 66 6c 65 20 47 72 6f 75 70 20 41 70 70 6c 69 63 61 74 69 6f 6e } //02 00  Ruffle Group Application
		$a_01_2 = {52 65 76 65 72 73 65 44 65 63 6f 64 65 } //02 00  ReverseDecode
		$a_01_3 = {42 69 74 54 72 65 65 44 65 63 6f 64 65 72 } //02 00  BitTreeDecoder
		$a_01_4 = {44 65 63 6f 6d 70 72 65 73 73 } //02 00  Decompress
		$a_01_5 = {43 6f 6e 66 75 73 65 64 42 79 41 74 74 72 69 62 75 74 65 } //00 00  ConfusedByAttribute
	condition:
		any of ($a_*)
 
}