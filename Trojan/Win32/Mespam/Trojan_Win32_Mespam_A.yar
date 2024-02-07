
rule Trojan_Win32_Mespam_A{
	meta:
		description = "Trojan:Win32/Mespam.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 09 00 09 00 00 02 00 "
		
	strings :
		$a_01_0 = {73 70 6f 72 64 65 72 2e 64 6c 6c } //03 00  sporder.dll
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 57 69 6e 53 6f 63 6b 32 5c 42 75 69 62 65 72 74 } //03 00  SOFTWARE\WinSock2\Buibert
		$a_01_2 = {72 73 76 70 33 32 5f 32 2e 64 6c 6c } //01 00  rsvp32_2.dll
		$a_01_3 = {57 53 43 57 72 69 74 65 50 72 6f 76 69 64 65 72 4f 72 64 65 72 } //01 00  WSCWriteProviderOrder
		$a_01_4 = {67 6f 62 6d 63 63 70 73 6d 72 6d 67 67 63 6f 6d 63 65 6e 6c 64 72 67 } //01 00  gobmccpsmrmggcomcenldrg
		$a_01_5 = {6e 72 6c 71 6f 6d 68 71 69 62 71 6a 73 71 64 65 72 71 70 6b 67 68 6c 72 6b } //01 00  nrlqomhqibqjsqderqpkghlrk
		$a_01_6 = {68 73 65 62 6e 66 6d 73 71 69 6a 6f 72 66 6a 6f 6f 6f 6e 63 6b 65 68 70 64 70 } //01 00  hsebnfmsqijorfjooonckehpdp
		$a_01_7 = {6b 64 67 66 6a 65 71 73 73 67 62 6c 62 73 68 67 6d 64 65 68 64 69 62 65 70 70 71 } //01 00  kdgfjeqssgblbshgmdehdibeppq
		$a_01_8 = {6b 73 62 73 73 6b 65 65 6e 6d 69 67 6b 62 63 66 68 6a 6a 65 72 66 6d 67 62 64 64 69 6e } //00 00  ksbsskeenmigkbcfhjjerfmgbddin
	condition:
		any of ($a_*)
 
}