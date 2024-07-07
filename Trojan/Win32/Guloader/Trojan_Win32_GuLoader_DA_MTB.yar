
rule Trojan_Win32_GuLoader_DA_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {75 00 6e 00 69 00 6e 00 76 00 61 00 64 00 61 00 62 00 6c 00 65 00 2e 00 65 00 78 00 65 00 } //1 uninvadable.exe
		$a_01_1 = {45 00 6e 00 65 00 72 00 67 00 69 00 73 00 69 00 6e 00 67 00 2e 00 62 00 69 00 6e 00 } //1 Energising.bin
		$a_01_2 = {53 00 75 00 70 00 65 00 72 00 65 00 76 00 69 00 64 00 65 00 6e 00 63 00 65 00 2e 00 69 00 6e 00 69 00 } //1 Superevidence.ini
		$a_01_3 = {45 00 64 00 64 00 69 00 65 00 2d 00 43 00 4c 00 49 00 2e 00 65 00 78 00 65 00 } //1 Eddie-CLI.exe
		$a_01_4 = {48 00 64 00 65 00 72 00 6b 00 72 00 6f 00 6e 00 65 00 74 00 32 00 33 00 37 00 2e 00 6c 00 6e 00 6b 00 } //1 Hderkronet237.lnk
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}