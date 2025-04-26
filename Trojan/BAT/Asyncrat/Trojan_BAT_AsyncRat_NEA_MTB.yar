
rule Trojan_BAT_AsyncRat_NEA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.NEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 0b 00 00 "
		
	strings :
		$a_01_0 = {6d 39 4f 49 4f 38 51 30 45 4b } //5 m9OIO8Q0EK
		$a_01_1 = {70 5a 62 6e 68 76 36 59 42 } //5 pZbnhv6YB
		$a_01_2 = {73 71 6b 70 69 6b 6f 73 2e 70 64 62 } //5 sqkpikos.pdb
		$a_01_3 = {6b 4c 6a 77 34 69 49 73 } //5 kLjw4iIs
		$a_01_4 = {36 32 45 36 46 31 33 42 35 33 44 36 37 46 44 44 37 38 30 } //4 62E6F13B53D67FDD780
		$a_01_5 = {34 44 36 39 37 35 32 30 39 39 37 42 43 33 } //4 4D697520997BC3
		$a_01_6 = {73 65 74 5f 43 72 65 61 74 65 4e 6f 57 69 6e 64 6f 77 } //3 set_CreateNoWindow
		$a_01_7 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 45 78 } //1 VirtualProtectEx
		$a_01_8 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_9 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //1 GetCurrentProcess
		$a_01_10 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //1 OpenProcess
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*4+(#a_01_5  & 1)*4+(#a_01_6  & 1)*3+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=35
 
}