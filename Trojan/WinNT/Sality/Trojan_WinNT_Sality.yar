
rule Trojan_WinNT_Sality{
	meta:
		description = "Trojan:WinNT/Sality,SIGNATURE_TYPE_PEHSTR_EXT,29 00 1e 00 08 00 00 "
		
	strings :
		$a_00_0 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 49 00 50 00 46 00 49 00 4c 00 54 00 45 00 52 00 44 00 52 00 49 00 56 00 45 00 52 00 } //10 \Device\IPFILTERDRIVER
		$a_00_1 = {50 73 54 65 72 6d 69 6e 61 74 65 53 79 73 74 65 6d 54 68 72 65 61 64 } //10 PsTerminateSystemThread
		$a_02_2 = {81 e2 ff ff 00 00 83 fa 90 01 01 74 0d 8b 45 90 01 01 25 ff ff 00 00 83 f8 90 01 01 75 07 b8 01 00 00 00 eb 90 01 01 c7 45 fc 00 00 00 00 eb 09 8b 4d fc 83 c1 01 89 4d fc 8b 55 fc 90 00 } //10
		$a_00_3 = {25 ff ff 00 00 25 00 ff 00 00 c1 f8 08 8b 4d 08 81 e1 ff ff 00 00 81 e1 ff 00 00 00 c1 e1 08 0b c1 } //10
		$a_00_4 = {6b 61 73 70 65 72 73 6b 79 } //1 kaspersky
		$a_00_5 = {76 69 72 75 73 74 6f 74 61 6c 2e } //1 virustotal.
		$a_00_6 = {73 61 6c 69 74 79 2d 72 65 6d 6f 76 } //1 sality-remov
		$a_00_7 = {68 74 74 70 3a 2f 2f 6b 75 6b 75 74 72 75 73 74 6e 65 74 } //1 http://kukutrustnet
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_02_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=30
 
}