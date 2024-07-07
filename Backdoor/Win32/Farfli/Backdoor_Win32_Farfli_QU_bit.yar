
rule Backdoor_Win32_Farfli_QU_bit{
	meta:
		description = "Backdoor:Win32/Farfli.QU!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {c6 45 f4 5c c6 45 f5 6f c6 45 f6 75 c6 45 f7 72 c6 45 f8 6c } //1
		$a_01_1 = {b8 12 00 cd 10 bd 18 7c b9 18 00 b8 01 13 bb 0c 00 ba 1d 0e cd 10 e2 fe 47 61 6d 65 20 4f 76 65 72 } //1
		$a_03_2 = {4b 50 8d 45 90 01 01 50 c6 45 90 01 01 45 c6 45 90 01 01 52 c6 45 90 01 01 4e c6 45 90 01 01 45 c6 45 90 01 01 4c c6 45 90 01 01 33 c6 45 90 01 01 32 90 00 } //1
		$a_03_3 = {8b 45 08 0f b7 cf 03 c6 8a 4c 4d 90 01 01 30 08 47 46 3b 75 90 00 } //1
		$a_01_4 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 25 73 } //1 SYSTEM\CurrentControlSet\Services\%s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}