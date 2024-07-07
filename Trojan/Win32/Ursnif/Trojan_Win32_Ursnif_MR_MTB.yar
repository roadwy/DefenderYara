
rule Trojan_Win32_Ursnif_MR_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.MR!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 42 61 72 73 65 6e 64 5c 57 61 72 53 74 72 65 74 63 68 5c 50 61 67 65 4d 75 73 74 5c 42 6f 74 74 6f 6d 69 6e 73 74 72 75 6d 65 6e 74 5c 47 72 6f 75 70 2e 70 64 62 } //1 c:\Barsend\WarStretch\PageMust\Bottominstrument\Group.pdb
		$a_01_1 = {47 72 6f 75 70 2e 64 6c 6c } //1 Group.dll
		$a_01_2 = {53 74 69 6c 6c 62 69 67 35 } //1 Stillbig5
		$a_01_3 = {49 6e 64 75 73 74 72 79 73 68 69 6e 65 38 } //1 Industryshine8
		$a_01_4 = {54 68 6f 75 67 68 74 77 68 6f 73 65 } //1 Thoughtwhose
		$a_01_5 = {54 00 61 00 69 00 6c 00 20 00 6e 00 6f 00 69 00 73 00 65 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 } //1 Tail noise Corporation
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}