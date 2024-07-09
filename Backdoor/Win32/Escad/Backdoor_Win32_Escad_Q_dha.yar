
rule Backdoor_Win32_Escad_Q_dha{
	meta:
		description = "Backdoor:Win32/Escad.Q!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {2f 47 52 41 4e 54 3a 65 76 65 72 79 6f 6e 65 2c 46 55 4c 4c [0-10] 5c 5c 25 73 5c 73 68 61 72 65 64 24 5c } //1
		$a_02_1 = {63 6d 64 2e 65 78 65 20 2f 63 20 [0-10] 2e 65 78 65 20 2f 6e 6f 64 65 3a 22 25 73 22 20 2f 75 73 65 72 3a 22 25 73 22 20 2f 70 61 73 73 77 6f 72 64 3a 22 25 73 22 20 50 52 4f 43 45 53 53 20 43 41 4c 4c 20 43 52 45 41 54 45 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}