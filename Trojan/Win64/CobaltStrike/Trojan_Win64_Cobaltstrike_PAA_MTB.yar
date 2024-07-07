
rule Trojan_Win64_Cobaltstrike_PAA_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 11 00 00 "
		
	strings :
		$a_81_0 = {6f 6b 75 77 77 67 65 66 71 65 67 2e 64 6c 6c } //1 okuwwgefqeg.dll
		$a_81_1 = {44 6c 6c 4d 61 69 6e 44 6c 6c } //1 DllMainDll
		$a_81_2 = {52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 RegisterServer
		$a_81_3 = {61 77 6f 77 61 63 63 69 69 75 77 61 6a 79 6e } //1 awowacciiuwajyn
		$a_81_4 = {62 72 6a 76 6e 79 79 61 6b 61 77 75 } //1 brjvnyyakawu
		$a_81_5 = {63 76 6d 67 67 68 72 73 70 71 61 65 63 6a } //1 cvmgghrspqaecj
		$a_81_6 = {64 73 74 69 6c 78 61 70 68 } //1 dstilxaph
		$a_81_7 = {69 65 6f 72 64 78 6d 76 79 70 } //1 ieordxmvyp
		$a_81_8 = {6b 6b 6b 75 69 65 68 74 7a 64 7a 75 65 61 } //1 kkkuiehtzdzuea
		$a_81_9 = {6d 7a 70 79 64 6a 6a 65 6e 61 78 7a 71 68 6d 6d 64 } //1 mzpydjjenaxzqhmmd
		$a_81_10 = {6e 6a 74 67 6b 63 64 6b 66 67 67 7a 6a 73 72 61 6d 6e 74 66 75 66 73 70 6e 70 66 6f 76 6c 69 74 } //1 njtgkcdkfggzjsramntfufspnpfovlit
		$a_81_11 = {6f 74 66 6d 76 66 75 74 6b 63 78 } //1 otfmvfutkcx
		$a_81_12 = {70 6f 76 6d 64 61 6a 61 79 73 6a 62 6e 6e } //1 povmdajaysjbnn
		$a_81_13 = {71 61 64 70 78 77 75 63 67 6a 75 79 } //1 qadpxwucgjuy
		$a_81_14 = {72 65 7a 75 69 75 63 67 } //1 rezuiucg
		$a_81_15 = {77 61 66 6b 6c 68 65 70 61 } //1 wafklhepa
		$a_81_16 = {77 7a 62 6a 6a 6d 71 76 72 64 74 76 62 6e 6c } //1 wzbjjmqvrdtvbnl
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1+(#a_81_15  & 1)*1+(#a_81_16  & 1)*1) >=17
 
}