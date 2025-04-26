
rule Trojan_Win32_Blopyfor_A_dha{
	meta:
		description = "Trojan:Win32/Blopyfor.A!dha,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 4f 4f 4b 20 42 65 61 63 6f 6e 20 53 6c 65 65 70 20 53 74 61 72 74 } //1 HOOK Beacon Sleep Start
		$a_01_1 = {48 4f 4f 4b 43 72 65 61 74 65 50 72 6f 63 65 73 73 49 6e 74 65 72 6e 61 6c 57 } //1 HOOKCreateProcessInternalW
		$a_01_2 = {48 4f 4f 4b 20 42 65 61 63 6f 6e 20 53 6c 65 65 70 20 45 6e 64 } //1 HOOK Beacon Sleep End
		$a_01_3 = {45 00 6e 00 74 00 65 00 72 00 20 00 41 00 63 00 63 00 6f 00 75 00 6e 00 74 00 20 00 49 00 6e 00 66 00 6f 00 72 00 6d 00 61 00 74 00 69 00 6f 00 6e 00 20 00 66 00 6f 00 72 00 20 00 54 00 61 00 73 00 6b 00 20 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 61 00 74 00 69 00 6f 00 6e 00 } //1 Enter Account Information for Task Registration
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}