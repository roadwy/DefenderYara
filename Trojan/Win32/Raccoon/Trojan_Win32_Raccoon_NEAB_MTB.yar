
rule Trojan_Win32_Raccoon_NEAB_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.NEAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 0c 83 2c 24 04 01 04 24 8b 44 24 08 8b 0c 24 31 08 59 } //5
		$a_01_1 = {8b 44 24 10 01 04 24 8b 44 24 0c 33 04 24 89 04 24 8b 44 24 08 8b 0c 24 89 08 } //5
		$a_01_2 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //2 IsProcessorFeaturePresent
		$a_01_3 = {54 65 72 6d 69 6e 61 74 65 50 72 6f 63 65 73 73 } //2 TerminateProcess
		$a_01_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //2 IsDebuggerPresent
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=16
 
}