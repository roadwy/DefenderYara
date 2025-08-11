
rule Backdoor_Win32_Kazuar_I_dha{
	meta:
		description = "Backdoor:Win32/Kazuar.I!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {24 00 70 00 61 00 79 00 6c 00 6f 00 61 00 64 00 5f 00 66 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 } //1 $payload_filename
		$a_01_1 = {25 00 6c 00 73 00 5c 00 25 00 6c 00 73 00 } //1 %ls\%ls
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}