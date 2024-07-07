
rule Trojan_Win32_Agent_DP{
	meta:
		description = "Trojan:Win32/Agent.DP,SIGNATURE_TYPE_PEHSTR_EXT,ffffff96 00 ffffff96 00 06 00 00 "
		
	strings :
		$a_02_0 = {f3 ab 66 ab aa c6 85 90 01 01 ff ff ff 5c c6 85 90 01 01 ff ff ff 73 c6 85 90 01 01 ff ff ff 76 c6 85 90 01 01 ff ff ff 63 c6 85 90 01 01 ff ff ff 68 c6 85 90 01 01 ff ff ff 6f c6 85 90 01 01 ff ff ff 73 c6 85 90 01 01 ff ff ff 74 c6 85 90 01 01 ff ff ff 2e c6 85 90 01 01 ff ff ff 65 c6 85 90 01 01 ff ff ff 78 c6 85 90 01 01 ff ff ff 65 80 a5 90 01 01 fe ff ff 00 6a 3f 90 00 } //100
		$a_00_1 = {44 6f 53 65 72 76 69 63 65 } //10 DoService
		$a_00_2 = {4f 70 65 6e 53 65 72 76 69 63 65 41 } //10 OpenServiceA
		$a_00_3 = {4f 70 65 6e 53 43 4d 61 6e 61 67 65 72 41 } //10 OpenSCManagerA
		$a_00_4 = {59 61 68 6f 6f 21 20 6d 65 73 73 65 6e 67 65 72 } //10 Yahoo! messenger
		$a_00_5 = {32 30 30 38 20 59 61 68 6f 6f 21 20 41 6c 6c 20 52 69 67 68 74 73 20 52 65 73 65 72 76 65 64 } //10 2008 Yahoo! All Rights Reserved
	condition:
		((#a_02_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*10) >=150
 
}