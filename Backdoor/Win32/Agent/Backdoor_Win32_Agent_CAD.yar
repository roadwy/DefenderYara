
rule Backdoor_Win32_Agent_CAD{
	meta:
		description = "Backdoor:Win32/Agent.CAD,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {72 75 6e 20 66 69 6c 65 20 73 75 63 65 73 73 } //1 run file sucess
		$a_01_1 = {73 65 6e 64 20 66 69 6c 65 20 73 75 63 65 73 73 } //1 send file sucess
		$a_01_2 = {63 6d 64 20 6b 69 6c 6c 65 64 } //1 cmd killed
		$a_01_3 = {63 6d 64 20 63 6f 6d 69 6e 67 } //1 cmd coming
		$a_01_4 = {69 00 6d 00 70 00 6c 00 65 00 6d 00 65 00 6e 00 74 00 61 00 74 00 69 00 6f 00 6e 00 66 00 69 00 6c 00 64 00 64 00 6c 00 6c 00 64 00 6c 00 73 00 65 00 66 00 77 00 65 00 66 00 77 00 65 00 66 00 } //1 implementationfilddlldlsefwefwef
		$a_01_5 = {6d 00 6d 00 74 00 61 00 73 00 6b 00 20 00 4d 00 46 00 43 00 20 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 } //1 mmtask MFC Application
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}