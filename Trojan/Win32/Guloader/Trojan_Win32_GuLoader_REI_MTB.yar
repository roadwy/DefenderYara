
rule Trojan_Win32_GuLoader_REI_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.REI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {5c 6b 6f 6e 64 65 6d 6e 61 74 69 6f 6e 65 72 6e 65 5c 65 6e 64 6f 64 6f 6e 74 69 63 61 6c 6c 79 5c 70 61 70 6f 75 6c 61 } //1 \kondemnationerne\endodontically\papoula
		$a_81_1 = {61 62 75 74 74 65 72 73 20 67 61 75 6c 65 69 74 65 72 20 74 6f 67 61 77 69 73 65 } //1 abutters gauleiter togawise
		$a_81_2 = {68 6f 76 65 64 73 61 65 74 6e 69 6e 67 } //1 hovedsaetning
		$a_81_3 = {65 71 75 69 63 6f 6e 74 69 6e 75 6f 75 73 } //1 equicontinuous
		$a_81_4 = {5c 4b 61 72 74 73 5c 61 75 74 6f 73 6f 6d 61 74 6f 67 6e 6f 73 69 73 2e 65 78 65 } //1 \Karts\autosomatognosis.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}