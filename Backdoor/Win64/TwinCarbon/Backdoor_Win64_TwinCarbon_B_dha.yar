
rule Backdoor_Win64_TwinCarbon_B_dha{
	meta:
		description = "Backdoor:Win64/TwinCarbon.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 6f 55 70 64 61 74 65 49 6e 73 74 61 6e 63 65 45 78 } //1 DoUpdateInstanceEx
		$a_01_1 = {67 65 74 5f 66 69 6c 65 } //1 get_file
		$a_01_2 = {70 75 74 5f 66 69 6c 65 } //1 put_file
		$a_01_3 = {73 6c 65 65 70 } //1 sleep
		$a_01_4 = {63 6c 6f 73 65 } //1 close
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}