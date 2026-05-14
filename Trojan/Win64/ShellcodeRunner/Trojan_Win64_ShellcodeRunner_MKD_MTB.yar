
rule Trojan_Win64_ShellcodeRunner_MKD_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.MKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 06 00 00 "
		
	strings :
		$a_01_0 = {48 69 20 66 72 6f 6d 20 52 65 64 20 54 65 61 6d 20 4f 70 65 72 61 74 6f 72 } //15 Hi from Red Team Operator
		$a_01_1 = {52 54 4f 3a 20 4d 61 6c 44 65 76 } //10 RTO: MalDev
		$a_01_2 = {5b 2b 5d 20 53 68 65 6c 6c 63 6f 64 65 20 77 72 69 74 74 65 6e 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //8 [+] Shellcode written successfully
		$a_01_3 = {5b 2b 5d 20 49 6e 6a 65 63 74 69 6f 6e 20 73 75 63 63 65 73 73 66 75 6c } //5 [+] Injection successful
		$a_01_4 = {5b 2b 5d 20 50 72 6f 63 65 73 73 20 68 61 6e 64 6c 65 20 6f 62 74 61 69 6e 65 64 } //3 [+] Process handle obtained
		$a_01_5 = {5b 2b 5d 20 52 65 6d 6f 74 65 20 74 68 72 65 61 64 20 63 72 65 61 74 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //2 [+] Remote thread created successfully
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10+(#a_01_2  & 1)*8+(#a_01_3  & 1)*5+(#a_01_4  & 1)*3+(#a_01_5  & 1)*2) >=40
 
}