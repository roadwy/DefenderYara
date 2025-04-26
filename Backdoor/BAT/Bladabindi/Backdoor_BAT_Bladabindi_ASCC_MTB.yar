
rule Backdoor_BAT_Bladabindi_ASCC_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.ASCC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {44 42 52 42 48 50 65 4b 6c 47 49 52 59 67 61 67 57 56 6d } //1 DBRBHPeKlGIRYgagWVm
		$a_01_1 = {58 75 41 4f 33 6c 65 34 43 36 57 6a 50 39 74 4d 78 49 48 } //1 XuAO3le4C6WjP9tMxIH
		$a_01_2 = {74 73 39 32 4d 73 65 4d 62 77 65 65 70 51 76 39 33 31 79 } //1 ts92MseMbweepQv931y
		$a_01_3 = {4f 41 58 64 37 49 63 77 55 42 31 39 35 79 4e 62 73 56 4b } //1 OAXd7IcwUB195yNbsVK
		$a_01_4 = {79 6e 49 68 43 4d 75 34 48 72 41 47 37 37 6f 4a 75 30 63 } //1 ynIhCMu4HrAG77oJu0c
		$a_01_5 = {56 57 37 69 76 6a 67 4b 76 4f 44 71 51 6d 52 71 72 63 6d } //1 VW7ivjgKvODqQmRqrcm
		$a_01_6 = {78 72 61 38 78 4f 59 41 43 63 5a 4c 4f 45 49 64 47 31 2e 37 51 50 4a 41 74 4a 4c 48 39 68 6b 4f 34 4e 65 78 39 } //1 xra8xOYACcZLOEIdG1.7QPJAtJLH9hkO4Nex9
		$a_01_7 = {24 66 62 39 64 66 66 36 30 2d 36 65 37 33 2d 34 31 33 63 2d 38 63 62 39 2d 31 35 65 31 30 31 64 37 34 37 37 33 } //1 $fb9dff60-6e73-413c-8cb9-15e101d74773
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}