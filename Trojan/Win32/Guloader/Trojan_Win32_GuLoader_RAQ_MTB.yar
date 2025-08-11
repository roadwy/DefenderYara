
rule Trojan_Win32_GuLoader_RAQ_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {25 61 6e 74 69 6d 6f 6e 6f 70 6f 6c 79 25 5c 6d 75 73 63 61 76 61 64 6f 5c 42 75 73 74 72 61 66 69 6b } //1 %antimonopoly%\muscavado\Bustrafik
		$a_81_1 = {72 75 74 61 74 65 20 6b 75 72 76 } //1 rutate kurv
		$a_81_2 = {68 61 6c 65 6e 65 73 73 65 73 20 74 72 79 6b 73 74 61 76 65 6c 73 65 73 20 75 6e 64 65 72 73 68 69 6e 65 } //1 halenesses trykstavelses undershine
		$a_81_3 = {73 69 72 75 70 20 76 75 6c 67 72 65 73 20 70 72 65 74 65 6e 74 69 6f 75 73 6e 65 73 73 65 73 } //1 sirup vulgres pretentiousnesses
		$a_81_4 = {6d 69 73 61 64 6a 75 73 74 20 6b 6f 6e 66 69 67 75 72 61 74 69 6f 6e 73 70 72 6f 67 72 61 6d 2e 65 78 65 } //1 misadjust konfigurationsprogram.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}