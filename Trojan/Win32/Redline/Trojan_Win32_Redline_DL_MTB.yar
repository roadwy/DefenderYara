
rule Trojan_Win32_Redline_DL_MTB{
	meta:
		description = "Trojan:Win32/Redline.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 49 00 8a 8c 02 3b 2d 0b 00 88 0c 30 40 3b 05 7c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Redline_DL_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6d 65 73 71 6a 63 6f 69 6a 67 64 64 72 69 6b 61 79 69 6f 64 69 61 65 75 64 67 6b 66 77 6b 69 77 64 78 63 68 75 71 67 76 67 6e 71 67 67 } //1 mesqjcoijgddrikayiodiaeudgkfwkiwdxchuqgvgnqgg
		$a_01_1 = {62 70 67 64 71 64 67 74 6e 6a 63 79 6a 71 6b 6d 67 77 64 69 74 75 7a 79 6f 76 70 6c 68 76 62 6f 6e 64 67 69 6c 6f 73 70 64 66 64 66 67 79 63 64 70 6c 6f 7a 74 69 72 6e 70 77 6e 61 74 61 6b 6c 61 72 70 6b 71 71 6b 74 74 7a 79 6e 66 76 62 70 67 6a 77 7a } //1 bpgdqdgtnjcyjqkmgwdituzyovplhvbondgilospdfdfgycdploztirnpwnataklarpkqqkttzynfvbpgjwz
		$a_01_2 = {63 64 6d 66 69 6a 78 61 66 6d 76 65 6d 66 7a 78 69 68 73 66 77 73 6d 70 65 79 61 64 69 64 6d } //1 cdmfijxafmvemfzxihsfwsmpeyadidm
		$a_01_3 = {74 62 72 69 73 63 78 7a 6b 7a 63 66 6c 66 75 6d 6b 69 6d 65 73 62 79 6f 65 62 6c 70 77 73 75 66 64 79 64 77 63 74 6f 72 66 74 65 70 76 79 } //1 tbriscxzkzcflfumkimesbyoeblpwsufdydwctorftepvy
		$a_01_4 = {72 73 69 77 73 69 64 65 77 78 79 71 75 6f 79 76 79 6c 70 69 61 77 62 6a 68 68 68 6e 78 75 6d 69 66 6a 69 6b 69 78 6a 7a } //1 rsiwsidewxyquoyvylpiawbjhhhnxumifjikixjz
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}