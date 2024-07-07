
rule Trojan_Win32_VB_QQ{
	meta:
		description = "Trojan:Win32/VB.QQ,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 00 3a 00 5c 00 46 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 73 00 20 00 61 00 6e 00 64 00 20 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 5c 00 4f 00 2e 00 44 00 2e 00 42 00 5c 00 46 00 46 00 20 00 44 00 44 00 44 00 44 00 44 00 44 00 44 00 46 00 73 00 } //1 F:\Focuments and Settings\O.D.B\FF DDDDDDDFs
		$a_01_1 = {4d 00 63 00 50 00 68 00 69 00 72 00 6f 00 73 00 } //1 McPhiros
		$a_01_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}