
rule Trojan_Win32_Vburses_PL{
	meta:
		description = "Trojan:Win32/Vburses.PL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 56 00 69 00 73 00 75 00 61 00 6c 00 20 00 53 00 74 00 75 00 64 00 69 00 6f 00 5c 00 56 00 42 00 39 00 38 00 5c 00 56 00 42 00 20 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 73 00 5c 00 56 00 69 00 72 00 75 00 73 00 65 00 73 00 5c 00 48 00 44 00 4b 00 50 00 34 00 5c 00 48 00 44 00 4b 00 50 00 5f 00 34 00 2e 00 76 00 62 00 70 00 } //1 \Program Files\Microsoft Visual Studio\VB98\VB Projects\Viruses\HDKP4\HDKP_4.vbp
		$a_01_1 = {53 00 61 00 79 00 20 00 47 00 6f 00 6f 00 64 00 42 00 79 00 65 00 20 00 54 00 6f 00 20 00 59 00 6f 00 75 00 72 00 20 00 48 00 61 00 72 00 64 00 20 00 44 00 72 00 69 00 76 00 65 00 } //1 Say GoodBye To Your Hard Drive
		$a_01_2 = {72 65 6d 20 41 75 74 68 6f 72 3a 20 4d 75 6e 67 61 20 42 75 6e 67 61 20 2d 20 66 72 6f 6d 20 41 75 73 74 72 61 6c 69 61 2c 20 74 68 65 20 6c 61 6e 64 20 66 75 6c 6c 20 6f 66 20 72 65 74 61 72 64 65 64 20 41 75 73 74 72 61 6c 69 61 6e } //1 rem Author: Munga Bunga - from Australia, the land full of retarded Australian
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}