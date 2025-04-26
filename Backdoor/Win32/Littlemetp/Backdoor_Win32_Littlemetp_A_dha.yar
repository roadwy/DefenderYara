
rule Backdoor_Win32_Littlemetp_A_dha{
	meta:
		description = "Backdoor:Win32/Littlemetp.A!dha,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 65 74 74 69 6e 67 20 74 68 65 20 66 69 6c 65 6e 61 6d 65 20 74 6f 20 22 32 5f 68 6f 73 74 2e 63 6f 6d 5f 34 34 33 2e 65 78 65 22 20 61 6e 64 20 72 75 6e 6e 69 6e 67 20 69 74 20 77 69 74 68 6f 75 74 20 61 72 67 73 20 77 69 6c 6c 20 64 6f 20 65 78 61 63 74 6c 79 20 74 68 65 20 73 61 6d 65 } //1 setting the filename to "2_host.com_443.exe" and running it without args will do exactly the same
		$a_01_1 = {33 3a 20 62 69 6e 64 5f 74 63 70 } //1 3: bind_tcp
		$a_01_2 = {6c 69 6b 65 20 54 52 41 4e 53 50 4f 52 54 5f 4c 48 4f 53 54 5f 4c 50 4f 52 54 2e 65 78 65 } //1 like TRANSPORT_LHOST_LPORT.exe
		$a_01_3 = {74 69 6e 79 6d 65 74 2e 65 78 65 } //1 tinymet.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}