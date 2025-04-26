
rule Backdoor_Win32_Zegost_decr{
	meta:
		description = "Backdoor:Win32/Zegost!decr,SIGNATURE_TYPE_PEHSTR_EXT,10 00 0f 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 44 00 62 00 78 00 55 00 70 00 64 00 61 00 74 00 65 00 42 00 54 00 5c 00 } //10 SOFTWARE\Microsoft\Windows\DbxUpdateBT\
		$a_00_1 = {49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 } //1 Install
		$a_00_2 = {42 00 54 00 46 00 6c 00 79 00 2e 00 64 00 75 00 6d 00 70 00 } //1 BTFly.dump
		$a_02_3 = {8a 0c 28 80 f1 ?? 88 0c 28 40 3b c3 7c f2 6a 40 68 00 10 00 00 53 6a 00 } //5
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*5) >=15
 
}