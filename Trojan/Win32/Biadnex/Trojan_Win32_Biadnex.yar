
rule Trojan_Win32_Biadnex{
	meta:
		description = "Trojan:Win32/Biadnex,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 3a 5c 57 6f 72 6b 5c 50 72 6f 6a 65 63 74 5c 56 53 5c 68 6f 75 73 65 5c 41 70 70 6c 65 5c 41 70 70 6c 65 5f 32 30 31 38 30 31 31 35 5c 52 65 6c 65 61 73 65 5c 49 6e 73 74 61 6c 6c 43 6c 69 65 6e 74 2e 70 64 62 00 00 } //1
		$a_01_1 = {65 67 73 76 72 33 32 2e 65 78 65 20 22 2f 75 20 62 69 74 73 61 64 6d 69 6e } //1 egsvr32.exe "/u bitsadmin
		$a_01_2 = {2f 63 61 6e 63 65 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 62 69 74 73 61 64 6d 69 6e 20 2f 61 64 64 66 69 62 69 74 73 61 64 6d 69 6e 20 2f 52 65 73 75 6d 62 69 74 73 61 64 6d 69 6e } //1 /canceft\windows\currebitsadmin /addfibitsadmin /Resumbitsadmin
		$a_01_3 = {2f 53 65 74 4e 6f 73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 74 69 66 79 43 6d 64 4c 69 6e 65 20 25 73 20 72 6c 65 20 25 73 } //1 /SetNosoftware\microsotifyCmdLine %s rle %s
		$a_01_4 = {69 74 73 61 64 6d 69 6e 20 2f 63 72 65 61 74 5c 73 79 73 74 65 6d 33 32 5c 6e 65 74 2e 65 78 } //1 itsadmin /creat\system32\net.ex
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}