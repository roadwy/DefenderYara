
rule Trojan_Win32_GuLoader_RAY_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {64 65 6d 6f 6b 72 61 74 69 65 72 6e 65 73 5c 68 6f 72 6f 67 72 61 70 68 5c 73 74 75 70 6f 72 69 66 69 63 } //1 demokratiernes\horograph\stuporific
		$a_81_1 = {25 74 68 75 72 73 74 25 5c 69 6e 64 73 6d 72 65 72 5c 77 61 6c 64 67 72 61 76 69 6e 65 } //1 %thurst%\indsmrer\waldgravine
		$a_81_2 = {68 79 67 72 6f 6d 65 74 65 72 73 20 73 79 67 65 73 69 6b 72 69 6e 67 65 72 6e 65 20 6a 61 70 61 6e 6f 6c 61 74 72 79 } //1 hygrometers sygesikringerne japanolatry
		$a_81_3 = {6b 61 6d 70 6b 75 6e 73 74 73 20 67 61 6d 62 75 73 69 61 20 73 6f 6e 64 72 69 6e 67 65 72 6e 65 } //1 kampkunsts gambusia sondringerne
		$a_81_4 = {61 6c 63 68 65 6d 69 73 74 65 72 2e 65 78 65 } //1 alchemister.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}