
rule Backdoor_Win64_UBoatRAT_A{
	meta:
		description = "Backdoor:Win64/UBoatRAT.A,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 6f 77 6e 66 69 6c 65 00 00 } //5
		$a_01_1 = {75 70 66 69 6c 65 00 00 } //5
		$a_03_2 = {62 69 74 73 61 64 6d 69 6e 20 2f 61 64 64 66 69 6c 65 20 [0-10] 20 63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c [0-10] 2e 65 78 65 20 20 25 25 74 65 6d 70 25 25 5c 73 79 73 2e 6c 6f 67 } //5
		$a_00_3 = {2e 00 62 00 61 00 74 00 00 00 00 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00 6f 00 70 00 65 00 6e 00 } //1
		$a_01_4 = {64 65 6c 20 25 25 30 } //1 del %%0
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_03_2  & 1)*5+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=17
 
}