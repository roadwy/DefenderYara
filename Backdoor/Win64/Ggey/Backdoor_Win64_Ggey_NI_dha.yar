
rule Backdoor_Win64_Ggey_NI_dha{
	meta:
		description = "Backdoor:Win64/Ggey.NI!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {69 c0 3f 00 01 00 48 8d 49 01 03 c2 0f b6 11 85 d2 75 ed 3d 0f 5a d8 38 } //1
		$a_03_1 = {48 c7 c1 02 00 00 80 48 8d 15 90 01 04 ff 15 90 01 04 85 c0 75 90 01 01 48 8b 90 01 03 48 8d 90 00 } //1
		$a_03_2 = {c7 44 24 28 04 00 00 00 48 8d 90 01 05 41 b9 04 00 00 00 48 89 44 24 20 45 33 c0 44 89 90 01 03 ff 15 90 01 04 85 c0 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}