
rule Trojan_Win32_TurtleLoader_Q{
	meta:
		description = "Trojan:Win32/TurtleLoader.Q,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {45 78 63 65 70 74 69 6f 6e 20 6f 63 63 75 72 72 65 64 20 64 75 72 69 6e 67 20 73 68 65 6c 6c 63 6f 64 65 20 65 78 65 63 75 74 69 6f 6e } //1 Exception occurred during shellcode execution
		$a_01_1 = {55 73 65 6c 65 73 73 20 73 74 72 69 6e 67 3a } //1 Useless string:
		$a_01_2 = {46 61 69 6c 65 64 20 74 6f 20 6c 6f 61 64 20 61 6e 64 20 65 78 65 63 75 74 65 20 73 68 65 6c 6c 63 6f 64 65 } //1 Failed to load and execute shellcode
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}