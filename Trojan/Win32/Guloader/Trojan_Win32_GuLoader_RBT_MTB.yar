
rule Trojan_Win32_GuLoader_RBT_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RBT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {25 72 65 75 6e 69 6f 6e 69 73 6d 25 5c 62 69 6c 6c 61 72 64 65 72 6e 65 5c 74 72 61 6e 73 70 6f 73 69 74 69 76 65 6c 79 } //1 %reunionism%\billarderne\transpositively
		$a_81_1 = {73 65 72 76 69 63 65 70 72 69 73 65 72 73 20 63 65 64 75 6c 65 20 66 75 72 72 6f 77 6c 69 6b 65 } //1 serviceprisers cedule furrowlike
		$a_81_2 = {6d 6f 70 70 65 72 6e 65 73 20 66 61 65 6e 67 73 6c 65 6e 64 65 20 73 63 69 6f 70 74 69 63 73 } //1 moppernes faengslende scioptics
		$a_81_3 = {73 74 61 61 6c 61 6d 70 65 73 20 75 6e 70 61 73 73 61 62 6c 65 6e 65 73 73 } //1 staalampes unpassableness
		$a_81_4 = {63 6f 6e 76 65 72 67 69 6e 67 20 61 6e 74 65 6e 6e 65 66 6f 72 65 6e 69 6e 67 65 72 6e 65 2e 65 78 65 } //1 converging antenneforeningerne.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}