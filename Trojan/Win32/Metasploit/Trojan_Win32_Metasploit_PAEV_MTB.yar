
rule Trojan_Win32_Metasploit_PAEV_MTB{
	meta:
		description = "Trojan:Win32/Metasploit.PAEV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 6c 6c 6f 63 61 74 69 6e 67 20 6d 65 6d 6f 72 79 20 69 6e 20 70 72 6f 63 65 73 73 } //1 Allocating memory in process
		$a_01_1 = {57 72 69 74 69 6e 67 20 73 68 65 6c 6c 63 6f 64 65 20 74 6f 20 70 72 6f 63 65 73 73 } //1 Writing shellcode to process
		$a_01_2 = {53 68 65 6c 6c 63 6f 64 65 20 69 73 20 77 72 69 74 74 65 6e 20 74 6f 20 6d 65 6d 6f 72 79 } //1 Shellcode is written to memory
		$a_01_3 = {57 72 69 74 69 6e 67 20 66 61 6b 65 20 73 75 62 63 6c 61 73 73 20 74 6f 20 70 72 6f 63 65 73 73 } //1 Writing fake subclass to process
		$a_01_4 = {54 72 69 67 67 65 72 69 6e 67 20 73 68 65 6c 6c 63 6f 64 65 2e 2e 2e 2e 21 21 21 } //1 Triggering shellcode....!!!
		$a_01_5 = {50 72 65 73 73 20 65 6e 74 65 72 20 74 6f 20 75 6e 68 6f 6f 6b 20 74 68 65 20 66 75 6e 63 74 69 6f 6e 20 61 6e 64 20 65 78 69 74 } //1 Press enter to unhook the function and exit
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}