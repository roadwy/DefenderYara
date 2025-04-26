
rule Trojan_BAT_Remcos_GB_MTB{
	meta:
		description = "Trojan:BAT/Remcos.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 0a 00 00 "
		
	strings :
		$a_80_0 = {25 73 79 73 74 65 6d 72 6f 6f 74 25 5c 4d 69 63 72 6f 73 6f 66 74 2e 4e 45 54 5c 46 72 61 6d 65 77 6f 72 6b 5c 76 34 2e 30 2e 33 30 33 31 39 5c 41 64 64 49 6e 50 72 6f 63 65 73 73 33 32 2e 65 78 65 } //%systemroot%\Microsoft.NET\Framework\v4.0.30319\AddInProcess32.exe  10
		$a_02_1 = {74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-14] 2e 00 [0-1e] 2e 00 72 00 75 00 2f 00 [0-28] 90 0a 96 00 68 00 } //10
		$a_02_2 = {74 74 70 73 3a 2f 2f [0-14] 2e [0-1e] 2e 72 75 2f [0-28] 90 0a 96 00 68 } //10
		$a_80_3 = {52 75 6e 6e 69 6e 67 } //Running  1
		$a_80_4 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //DownloadString  1
		$a_80_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  1
		$a_80_6 = {64 69 73 43 6f 6e 6e 65 63 74 } //disConnect  1
		$a_80_7 = {53 6f 63 6b 65 74 53 68 75 74 64 6f 77 6e } //SocketShutdown  1
		$a_80_8 = {70 61 79 6c 6f 61 64 } //payload  1
		$a_80_9 = {41 74 74 61 63 6b } //Attack  1
	condition:
		((#a_80_0  & 1)*10+(#a_02_1  & 1)*10+(#a_02_2  & 1)*10+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1) >=25
 
}