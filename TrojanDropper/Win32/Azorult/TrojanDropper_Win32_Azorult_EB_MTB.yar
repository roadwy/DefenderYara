
rule TrojanDropper_Win32_Azorult_EB_MTB{
	meta:
		description = "TrojanDropper:Win32/Azorult.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {47 55 53 65 61 72 63 68 65 72 20 31 2e 33 2e 32 2e 38 35 } //1 GUSearcher 1.3.2.85
		$a_01_1 = {7b 32 62 31 36 61 33 38 45 2d 39 31 42 34 2d 34 39 31 30 2d 39 30 30 36 2d 31 38 66 62 32 35 37 36 39 33 34 62 7d } //1 {2b16a38E-91B4-4910-9006-18fb2576934b}
		$a_01_2 = {7b 73 79 73 75 73 65 72 69 6e 66 6f 6e 61 6d 65 7d } //1 {sysuserinfoname}
		$a_01_3 = {7b 73 79 73 75 73 65 72 69 6e 66 6f 6f 72 67 7d } //1 {sysuserinfoorg}
		$a_01_4 = {41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 69 00 6f 00 6e 00 73 00 76 00 65 00 72 00 6b 00 74 00 79 00 } //1 Administrationsverkty
		$a_01_5 = {53 68 65 6c 6c 45 78 65 63 75 74 65 45 78 41 } //1 ShellExecuteExA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}