
rule Trojan_Win32_GuLoader_RSF_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RSF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {64 6f 6d 6d 65 64 61 67 73 70 72 64 69 6b 65 6e 65 6e 73 20 6a 6f 68 6e 6e 69 73 } //1 dommedagsprdikenens johnnis
		$a_81_1 = {76 69 67 6e 65 74 74 65 64 } //1 vignetted
		$a_81_2 = {6b 6f 64 65 73 } //1 kodes
		$a_81_3 = {74 6f 67 67 6c 65 72 20 74 72 69 75 6d 76 69 72 61 74 65 73 2e 65 78 65 } //1 toggler triumvirates.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}