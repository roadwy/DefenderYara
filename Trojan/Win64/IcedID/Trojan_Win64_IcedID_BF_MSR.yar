
rule Trojan_Win64_IcedID_BF_MSR{
	meta:
		description = "Trojan:Win64/IcedID.BF!MSR,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 08 00 00 "
		
	strings :
		$a_01_0 = {4d 68 48 6b 44 4f 50 41 57 44 4d } //2 MhHkDOPAWDM
		$a_01_1 = {50 41 69 56 68 67 44 65 79 4f 63 } //2 PAiVhgDeyOc
		$a_01_2 = {51 4b 67 4b 55 4e 65 73 42 6e 76 55 78 64 } //2 QKgKUNesBnvUxd
		$a_01_3 = {52 62 59 62 75 72 42 53 53 6b 50 6b 4a } //2 RbYburBSSkPkJ
		$a_01_4 = {54 50 65 6a 58 6a 50 65 53 75 66 4a 62 6b 71 } //2 TPejXjPeSufJbkq
		$a_01_5 = {55 46 53 65 6c 6c 75 64 48 75 66 6e 64 75 } //2 UFSelludHufndu
		$a_01_6 = {65 6d 70 78 46 7a 67 4a 71 51 53 5a 6f 69 61 } //2 empxFzgJqQSZoia
		$a_01_7 = {67 56 4c 4f 53 78 54 75 46 64 4a 6f 52 4c 43 70 } //2 gVLOSxTuFdJoRLCp
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2) >=16
 
}