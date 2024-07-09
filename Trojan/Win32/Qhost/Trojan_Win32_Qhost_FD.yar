
rule Trojan_Win32_Qhost_FD{
	meta:
		description = "Trojan:Win32/Qhost.FD,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {24 24 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 00 [0-10] fd 9a 80 5c 69 6e 65 74 63 2e 64 6c 6c 00 2f 65 6e 64 00 } //1
		$a_01_1 = {65 78 65 00 68 74 74 70 3a 2f 2f 71 76 63 2e 63 6f 6d 2f 63 67 65 6e 2f 63 64 69 2e 6a 70 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}