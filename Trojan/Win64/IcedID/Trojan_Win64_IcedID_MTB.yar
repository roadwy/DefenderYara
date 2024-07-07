
rule Trojan_Win64_IcedID_MTB{
	meta:
		description = "Trojan:Win64/IcedID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6d 4f 52 43 4c 2e 64 6c 6c } //1 mORCL.dll
		$a_01_1 = {42 77 74 77 38 75 34 6c 4e 43 47 38 63 79 63 6f 77 31 76 31 78 71 45 63 78 39 61 } //1 Bwtw8u4lNCG8cycow1v1xqEcx9a
		$a_01_2 = {43 79 4f 4a 69 4a 41 45 53 63 56 4b 31 70 66 32 6e 70 } //1 CyOJiJAEScVK1pf2np
		$a_01_3 = {44 32 66 76 6d 39 78 75 36 37 39 70 4b 73 63 36 58 } //1 D2fvm9xu679pKsc6X
		$a_01_4 = {45 34 79 36 38 69 52 7a 5a 31 4f 69 32 68 79 64 42 48 5a 78 51 58 51 6c 67 4e 66 73 32 } //1 E4y68iRzZ1Oi2hydBHZxQXQlgNfs2
		$a_01_5 = {46 44 77 73 32 74 6f 73 74 47 6a 5a 45 5a 65 74 47 6d 6e 4d } //1 FDws2tostGjZEZetGmnM
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}