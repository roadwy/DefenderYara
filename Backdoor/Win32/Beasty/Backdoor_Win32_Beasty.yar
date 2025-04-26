
rule Backdoor_Win32_Beasty{
	meta:
		description = "Backdoor:Win32/Beasty,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 65 74 20 63 64 61 75 64 69 6f 20 64 6f 6f 72 20 6f 70 65 6e } //1 set cdaudio door open
		$a_01_1 = {2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 20 42 6f 6f 74 3a 5b } //1 ************ Boot:[
		$a_01_2 = {43 68 61 74 20 73 65 73 73 69 6f 6e 20 73 74 61 72 74 65 64 20 62 79 20 } //1 Chat session started by 
		$a_01_3 = {6d 73 6c 00 47 65 74 53 63 72 65 65 6e 00 00 00 47 65 74 57 65 62 43 61 6d } //1
		$a_01_4 = {47 65 74 5f 43 61 6d 00 47 5f 53 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}