
rule Backdoor_Win32_Phonzy_A{
	meta:
		description = "Backdoor:Win32/Phonzy.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {73 76 63 68 6f 73 74 2e 65 78 65 } //1 svchost.exe
		$a_81_1 = {50 4c 49 4e 4b 5f 50 52 4f 54 4f 43 4f 4c } //1 PLINK_PROTOCOL
		$a_81_2 = {50 6c 69 6e 6b 3a 20 63 6f 6d 6d 61 6e 64 2d 6c 69 6e 65 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 75 74 69 6c 69 74 79 } //1 Plink: command-line connection utility
		$a_81_3 = {4c 56 4d 4c 4f 47 46 } //1 LVMLOGF
		$a_81_4 = {6e 6f 6c 6f 67 69 6e 40 77 77 77 2e 67 65 73 75 63 68 74 2e 6e 65 74 } //1 nologin@www.gesucht.net
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}