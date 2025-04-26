
rule Trojan_BAT_Bladabindi_AM_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {74 61 69 66 69 6c 65 6d 6f 69 31 } //1 taifilemoi1
		$a_01_1 = {55 70 64 61 74 61 2e 65 78 65 } //1 Updata.exe
		$a_01_2 = {63 00 68 00 65 00 63 00 6b 00 2e 00 74 00 78 00 74 00 } //1 check.txt
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_01_4 = {74 61 69 6d 75 74 69 } //1 taimuti
		$a_01_5 = {67 65 74 5f 4b 68 61 6b 69 } //1 get_Khaki
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Trojan_BAT_Bladabindi_AM_MTB_2{
	meta:
		description = "Trojan:BAT/Bladabindi.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {fa 25 33 00 16 00 00 01 00 00 00 2a 00 00 00 0c 00 00 00 2b 00 00 00 36 00 00 00 32 00 00 00 10 } //2
		$a_01_1 = {52 75 66 66 6c 65 20 47 72 6f 75 70 20 41 70 70 6c 69 63 61 74 69 6f 6e } //2 Ruffle Group Application
		$a_01_2 = {52 65 76 65 72 73 65 44 65 63 6f 64 65 } //2 ReverseDecode
		$a_01_3 = {42 69 74 54 72 65 65 44 65 63 6f 64 65 72 } //2 BitTreeDecoder
		$a_01_4 = {44 65 63 6f 6d 70 72 65 73 73 } //2 Decompress
		$a_01_5 = {43 6f 6e 66 75 73 65 64 42 79 41 74 74 72 69 62 75 74 65 } //2 ConfusedByAttribute
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=12
 
}