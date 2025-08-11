
rule Trojan_Win32_GuLoader_RAL_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {5c 73 6f 76 6a 65 74 74 65 6e 5c 70 72 69 76 61 74 65 6e 65 73 73 } //1 \sovjetten\privateness
		$a_81_1 = {25 61 66 62 69 6c 64 6e 69 6e 67 65 72 25 5c 68 6f 76 65 64 74 6a 5c 73 61 6c 61 62 6c 79 2e 6a 70 67 } //1 %afbildninger%\hovedtj\salably.jpg
		$a_81_2 = {69 6e 64 73 65 6a 6c 65 6e 64 65 73 20 63 6f 6c 6f 70 74 6f 73 69 73 } //1 indsejlendes coloptosis
		$a_81_3 = {73 70 6f 6e 73 6f 6e } //1 sponson
		$a_81_4 = {72 68 79 6d 65 6d 61 6b 69 6e 67 20 70 69 6c 74 61 73 74 65 6e 73 2e 65 78 65 } //1 rhymemaking piltastens.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}