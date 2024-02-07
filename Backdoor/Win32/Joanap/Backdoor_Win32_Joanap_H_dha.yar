
rule Backdoor_Win32_Joanap_H_dha{
	meta:
		description = "Backdoor:Win32/Joanap.H!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {25 73 62 00 25 73 5c 53 79 73 57 4f 57 36 34 00 } //01 00  猥b猥卜獹佗㙗4
		$a_00_1 = {00 56 42 6f 78 48 6f 6f 6b 4e 6f 74 69 66 79 45 76 65 6e 74 00 56 4d 77 61 72 65 55 73 65 72 4d 61 6e 61 67 65 72 45 76 65 6e 74 00 } //01 00  嘀潂䡸潯乫瑯晩䕹敶瑮嘀睍牡啥敳䵲湡条牥癅湥t
		$a_00_2 = {00 6d 69 6e 69 2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e 00 } //01 00 
		$a_01_3 = {5f 5e 88 41 0e 5d 88 11 33 c2 } //00 00 
	condition:
		any of ($a_*)
 
}