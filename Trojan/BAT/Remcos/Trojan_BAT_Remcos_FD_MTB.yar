
rule Trojan_BAT_Remcos_FD_MTB{
	meta:
		description = "Trojan:BAT/Remcos.FD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {5c 6b 69 69 63 68 69 5c 77 6f 72 6b 5c 49 6d 61 67 65 52 65 73 69 7a 65 54 65 73 74 5c 67 65 6f 2d 65 6c 65 76 61 74 69 6f 6e 2e 70 6e 67 } //1 \kiichi\work\ImageResizeTest\geo-elevation.png
		$a_81_1 = {41 6e 79 44 65 73 6b 20 53 6f 66 74 77 61 72 65 20 47 6d 62 48 } //1 AnyDesk Software GmbH
		$a_81_2 = {31 32 37 2e 30 2e 30 2e 31 3a 38 30 38 31 } //1 127.0.0.1:8081
		$a_81_3 = {6c 6f 63 61 6c 68 6f 73 74 3a 38 30 38 31 } //1 localhost:8081
		$a_81_4 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_81_5 = {46 6f 72 6d 54 65 73 74 } //1 FormTest
		$a_81_6 = {54 6f 53 74 72 69 6e 67 } //1 ToString
		$a_81_7 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_8 = {53 6c 65 65 70 } //1 Sleep
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}