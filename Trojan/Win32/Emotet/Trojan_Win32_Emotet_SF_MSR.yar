
rule Trojan_Win32_Emotet_SF_MSR{
	meta:
		description = "Trojan:Win32/Emotet.SF!MSR,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {76 69 65 77 65 78 64 2e 64 6c 6c } //1 viewexd.dll
		$a_01_1 = {4c 6f 63 6b 46 69 6c 65 } //1 LockFile
		$a_01_2 = {26 00 48 00 69 00 64 00 65 00 } //1 &Hide
		$a_01_3 = {61 00 63 00 63 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 } //1 accDescription
		$a_01_4 = {4e 6f 4e 65 74 43 6f 6e 6e 65 63 74 44 69 73 63 6f 6e 6e 65 63 74 } //1 NoNetConnectDisconnect
		$a_01_5 = {52 65 63 65 6e 74 44 6f 63 73 48 69 73 74 6f 72 79 } //1 RecentDocsHistory
		$a_01_6 = {63 00 72 00 65 00 61 00 74 00 65 00 20 00 65 00 6d 00 70 00 74 00 79 00 20 00 64 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 } //1 create empty document
		$a_01_7 = {65 00 6e 00 74 00 65 00 72 00 20 00 61 00 20 00 63 00 75 00 72 00 72 00 65 00 6e 00 63 00 79 00 } //1 enter a currency
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}