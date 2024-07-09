
rule Trojan_Win32_Azorult_CD_MTB{
	meta:
		description = "Trojan:Win32/Azorult.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {8a 8c 01 3b 2d 0b 00 8b 15 [0-04] 88 0c 02 8b 15 [0-04] 40 3b c2 72 df } //2
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}
rule Trojan_Win32_Azorult_CD_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.CD!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 44 24 20 50 6a 00 ff d6 6a 00 8d 8c 24 54 18 00 00 51 ff d7 8d 54 24 28 52 ff d3 8d 44 24 24 50 c7 44 24 28 00 00 00 00 ff d5 6a 00 8d 8c 24 54 10 00 00 51 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}