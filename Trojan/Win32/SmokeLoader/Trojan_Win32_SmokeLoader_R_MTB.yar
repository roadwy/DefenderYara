
rule Trojan_Win32_SmokeLoader_R_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 0c 30 04 31 46 3b f7 7c d0 } //4
		$a_01_1 = {74 75 67 6f 78 75 70 69 6a 65 62 75 76 69 7a 61 6e 69 67 69 6a 65 76 61 77 69 78 6f 6c 75 74 75 } //1 tugoxupijebuvizanigijevawixolutu
		$a_01_2 = {78 69 6d 61 77 61 7a 75 64 69 6b 61 68 65 66 61 66 6f 70 6f 70 6f 72 69 66 6f 7a 69 62 20 6b 61 64 61 6d 75 7a 61 79 65 63 65 70 20 68 69 7a 75 6a 61 6a 75 67 65 6a 75 73 61 77 61 68 61 72 69 64 61 6d 20 77 75 6e 6f 67 75 7a 61 7a 61 70 65 67 75 76 65 63 61 7a 61 67 65 67 61 6e 75 7a 69 } //1 ximawazudikahefafopoporifozib kadamuzayecep hizujajugejusawaharidam wunoguzazapeguvecazageganuzi
		$a_01_3 = {6e 69 6e 75 63 65 74 75 77 6f 64 69 7a 61 74 61 62 69 73 69 68 61 79 61 63 69 78 } //1 ninucetuwodizatabisihayacix
		$a_01_4 = {68 6f 76 6f 63 61 66 69 73 61 76 65 78 75 6a 65 67 69 73 65 6c 61 6e 6f } //1 hovocafisavexujegiselano
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}