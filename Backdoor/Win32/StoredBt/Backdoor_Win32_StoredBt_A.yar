
rule Backdoor_Win32_StoredBt_A{
	meta:
		description = "Backdoor:Win32/StoredBt.A,SIGNATURE_TYPE_PEHSTR_EXT,09 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 65 73 75 6c 74 3a 20 5b 53 75 63 63 65 73 73 20 74 6f 20 6c 61 75 6e 63 68 20 72 63 76 6e 63 20 63 6f 6d 6d 61 6e 64 20 25 73 3a 25 64 5d } //2 Result: [Success to launch rcvnc command %s:%d]
		$a_01_1 = {2f 5f 63 6d 6e 2f 49 4e 49 2f 63 61 2e 69 6e 69 } //2 /_cmn/INI/ca.ini
		$a_01_2 = {63 61 70 74 75 72 65 20 69 73 20 73 75 63 63 65 73 73 66 75 6c 2e 20 63 68 65 63 6b 20 74 68 65 20 4c 4f 47 20 64 69 72 65 63 74 6f 72 79 20 61 66 74 65 72 20 61 20 66 65 77 20 6d 69 6e 75 74 65 73 2e } //3 capture is successful. check the LOG directory after a few minutes.
		$a_01_3 = {49 6e 74 65 72 6e 61 6c 43 6f 6d 6d 61 6e 64 3a 20 5b 62 74 73 74 6f 70 5d } //2 InternalCommand: [btstop]
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2) >=6
 
}