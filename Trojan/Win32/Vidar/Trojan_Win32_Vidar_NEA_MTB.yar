
rule Trojan_Win32_Vidar_NEA_MTB{
	meta:
		description = "Trojan:Win32/Vidar.NEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1c 00 07 00 00 "
		
	strings :
		$a_01_0 = {54 61 6e 67 72 61 6d 34 2e 65 78 65 } //10 Tangram4.exe
		$a_01_1 = {57 69 6e 61 70 69 2e 51 6f 73 } //5 Winapi.Qos
		$a_01_2 = {31 2e 50 61 63 6b 24 32 33 31 24 41 63 74 52 65 63 } //5 1.Pack$231$ActRec
		$a_01_3 = {44 24 48 50 6b 44 24 54 64 50 56 } //5 D$HPkD$TdPV
		$a_01_4 = {45 78 74 46 6c 6f 6f 64 46 69 6c 6c } //1 ExtFloodFill
		$a_01_5 = {53 79 73 74 65 6d 2e 57 69 6e 2e 54 61 73 6b 62 61 72 43 6f 72 65 } //1 System.Win.TaskbarCore
		$a_01_6 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=28
 
}