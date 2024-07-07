
rule Trojan_Win32_Convagent_DE_MTB{
	meta:
		description = "Trojan:Win32/Convagent.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {8a 04 02 32 04 19 88 03 8d 45 90 50 ff d6 } //4
		$a_01_1 = {36 32 2e 32 30 34 2e 34 31 2e 31 32 36 } //2 62.204.41.126
		$a_01_2 = {35 31 2e 31 39 35 2e 31 36 36 2e 31 38 39 } //2 51.195.166.189
		$a_01_3 = {31 36 38 2e 31 31 39 2e 35 39 2e 32 31 31 } //2 168.119.59.211
		$a_01_4 = {42 69 74 63 6f 69 6e 5c 77 61 6c 6c 65 74 73 } //1 Bitcoin\wallets
		$a_01_5 = {44 6f 77 6e 6c 6f 61 64 73 5c 25 73 5f 25 73 2e 74 78 74 } //1 Downloads\%s_%s.txt
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}