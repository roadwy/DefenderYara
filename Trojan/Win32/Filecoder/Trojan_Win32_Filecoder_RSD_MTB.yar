
rule Trojan_Win32_Filecoder_RSD_MTB{
	meta:
		description = "Trojan:Win32/Filecoder.RSD!MTB,SIGNATURE_TYPE_PEHSTR,09 00 09 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 68 61 64 6f 77 63 6f 70 79 20 64 65 6c 65 74 65 } //1 shadowcopy delete
		$a_01_1 = {63 6c 65 61 72 20 76 73 73 } //1 clear vss
		$a_01_2 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 CurrentVersion\Run
		$a_01_3 = {73 65 74 74 69 6e 67 20 77 61 6c 6c 70 61 70 65 72 } //1 setting wallpaper
		$a_01_4 = {79 00 61 00 72 00 74 00 74 00 64 00 6e 00 2e 00 64 00 65 00 } //5 yarttdn.de
		$a_01_5 = {6c 00 6f 00 6c 00 6f 00 6c 00 } //5 lolol
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5) >=9
 
}