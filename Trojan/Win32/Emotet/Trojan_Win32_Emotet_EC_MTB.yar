
rule Trojan_Win32_Emotet_EC_MTB{
	meta:
		description = "Trojan:Win32/Emotet.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 00 66 00 74 00 68 00 65 00 61 00 69 00 72 00 73 00 75 00 62 00 64 00 75 00 65 00 2e 00 56 00 44 00 64 00 73 00 } //1 rftheairsubdue.VDds
		$a_01_1 = {48 00 69 00 6d 00 61 00 67 00 65 00 61 00 70 00 70 00 65 00 61 00 72 00 } //1 Himageappear
		$a_01_2 = {6d 00 6f 00 76 00 69 00 6e 00 67 00 63 00 5a 00 6c 00 69 00 66 00 65 00 76 00 6f 00 69 00 64 00 64 00 61 00 72 00 6b 00 6e 00 65 00 73 00 73 00 35 00 } //1 movingcZlifevoiddarkness5
		$a_01_3 = {69 00 74 00 67 00 72 00 65 00 61 00 74 00 63 00 72 00 65 00 65 00 70 00 69 00 6e 00 67 00 74 00 72 00 65 00 65 00 2e 00 6c 00 63 00 72 00 65 00 65 00 70 00 65 00 74 00 68 00 } //1 itgreatcreepingtree.lcreepeth
		$a_01_4 = {54 00 65 00 73 00 74 00 61 00 70 00 70 00 2e 00 65 00 78 00 65 00 } //1 Testapp.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Emotet_EC_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.EC!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 5c 5b 07 0f af da 8b d7 2b d0 03 d2 03 d2 2b d3 8b 5c 24 1c 0f af de 03 d6 8d 54 95 00 8d 1c 5b 03 db 03 db bd 10 00 00 00 2b eb 8b 5c 24 10 0f af e9 03 d5 03 53 20 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}