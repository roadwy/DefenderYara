
rule Trojan_Win32_Agent_BUI{
	meta:
		description = "Trojan:Win32/Agent.BUI,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1e 00 04 00 00 "
		
	strings :
		$a_03_0 = {44 4c 4c 53 54 41 52 54 45 52 2e 64 6c 6c 00 90 04 04 03 61 2d 7a 00 00 90 00 } //10
		$a_01_1 = {25 30 38 58 2e 64 6c 6c } //10 %08X.dll
		$a_01_2 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 20 00 41 00 6c 00 6c 00 20 00 72 00 69 00 67 00 68 00 74 00 73 00 20 00 72 00 65 00 73 00 65 00 72 00 76 00 65 00 64 00 2e 00 } //1 Microsoft Corporation. All rights reserved.
		$a_01_3 = {c7 45 0c 9a 02 00 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*10) >=30
 
}