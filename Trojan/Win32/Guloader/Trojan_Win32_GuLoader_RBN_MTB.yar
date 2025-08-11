
rule Trojan_Win32_GuLoader_RBN_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 69 65 64 20 57 61 73 74 65 20 49 6e 64 75 73 74 72 69 65 73 2c 20 49 6e 63 2e } //1 Allied Waste Industries, Inc.
		$a_81_1 = {4d 65 74 61 6c 64 79 6e 65 20 43 6f 72 70 6f 72 61 74 69 6f 6e } //1 Metaldyne Corporation
		$a_81_2 = {53 6f 75 74 68 77 65 73 74 20 41 69 72 6c 69 6e 65 73 20 43 6f } //1 Southwest Airlines Co
		$a_81_3 = {66 6f 72 6d 62 6c 69 6e 67 65 6e 20 73 74 61 74 75 73 65 73 2e 65 78 65 } //1 formblingen statuses.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Trojan_Win32_GuLoader_RBN_MTB_2{
	meta:
		description = "Trojan:Win32/GuLoader.RBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {23 5c 62 72 69 73 6b 6c 79 5c 74 6f 77 6e 68 6f 75 73 65 73 5c 49 6e 66 6f 72 6d 61 74 69 6f 6e 73 62 65 68 61 6e 64 6c 69 6e 67 38 30 } //1 #\briskly\townhouses\Informationsbehandling80
		$a_81_1 = {24 24 5c 75 6e 66 72 69 67 69 64 6e 65 73 73 5c 70 72 73 65 6e 74 61 74 69 6f 6e 2e 75 6e 65 } //1 $$\unfrigidness\prsentation.une
		$a_81_2 = {38 38 5c 42 6c 75 65 6a 65 6c 6c 79 37 38 5c 69 6e 66 69 6e 69 74 75 70 6c 65 2e 74 65 74 } //1 88\Bluejelly78\infinituple.tet
		$a_81_3 = {64 72 61 6d 61 65 74 20 74 72 69 66 6c 69 65 72 20 64 69 72 69 67 65 6e 74 65 72 6e 65 73 } //1 dramaet triflier dirigenternes
		$a_81_4 = {62 72 69 64 67 65 6d 61 6b 69 6e 67 20 72 67 6e 69 6e 67 65 6e 73 } //1 bridgemaking rgningens
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule Trojan_Win32_GuLoader_RBN_MTB_3{
	meta:
		description = "Trojan:Win32/GuLoader.RBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {73 6f 76 73 65 73 6b 65 65 72 6e 65 73 5c 75 6e 63 6f 6d 70 6c 69 61 62 69 6c 69 74 79 5c 6b 72 69 74 65 72 69 65 72 6e 65 73 } //1 sovseskeernes\uncompliability\kriteriernes
		$a_81_1 = {25 55 6e 70 72 69 73 6f 6e 61 62 6c 65 25 5c 4f 6e 6f 6d 61 73 74 69 63 61 6c 5c 44 69 73 6b 75 72 73 65 72 2e 75 6e 74 } //1 %Unprisonable%\Onomastical\Diskurser.unt
		$a_81_2 = {65 6e 63 79 6b 6c 6f 70 64 69 65 72 73 20 69 6e 64 69 73 73 6f 6c 75 62 6c 79 20 61 66 73 70 6e 64 69 6e 67 73 6d 69 64 6c 65 72 6e 65 73 } //1 encyklopdiers indissolubly afspndingsmidlernes
		$a_81_3 = {6e 6f 6e 74 65 6e 74 61 74 69 76 65 20 66 6c 6f 70 70 65 6e 65 73 20 61 6d 70 6c 69 74 75 64 65 72 73 } //1 nontentative floppenes amplituders
		$a_81_4 = {73 65 6d 65 6e 74 65 72 61 } //1 sementera
		$a_81_5 = {72 65 70 72 6f 63 6c 61 69 6d } //1 reproclaim
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}