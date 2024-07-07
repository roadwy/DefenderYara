
rule Backdoor_Win32_Skpark_A_MTB{
	meta:
		description = "Backdoor:Win32/Skpark.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {2f 70 6f 73 74 } //1 /post
		$a_01_1 = {6c 61 73 74 5f 73 65 65 6e } //1 last_seen
		$a_01_2 = {73 68 65 6c 6c 5f 65 78 65 63 } //1 shell_exec
		$a_01_3 = {53 4b 38 50 41 52 4b } //1 SK8PARK
		$a_01_4 = {6d 61 63 61 72 6f 6f 6e 3d } //1 macaroon=
		$a_01_5 = {2f 73 74 61 67 65 30 } //1 /stage0
		$a_01_6 = {2f 73 74 61 67 65 31 } //1 /stage1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}