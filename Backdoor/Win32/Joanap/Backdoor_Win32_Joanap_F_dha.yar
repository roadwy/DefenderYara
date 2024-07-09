
rule Backdoor_Win32_Joanap_F_dha{
	meta:
		description = "Backdoor:Win32/Joanap.F!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {25 73 5c 25 73 [0-10] 64 76 70 69 2e 64 6e 61 [0-0a] 25 73 [0-0a] 2e 64 6c 6c } //1
		$a_02_1 = {64 65 6c 20 2f 61 20 22 25 73 22 [0-10] 69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}