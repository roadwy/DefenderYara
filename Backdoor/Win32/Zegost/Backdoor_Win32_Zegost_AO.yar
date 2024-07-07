
rule Backdoor_Win32_Zegost_AO{
	meta:
		description = "Backdoor:Win32/Zegost.AO,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 44 61 72 6b 53 68 65 6c 6c 5c 44 53 5f 53 65 72 76 65 72 } //2 \DarkShell\DS_Server
		$a_01_1 = {73 65 73 65 2d 61 76 2e 69 6e } //1 sese-av.in
		$a_01_2 = {43 6c 69 65 6e 74 20 68 6f 6f 6b 20 66 72 65 65 20 66 61 69 6c 75 72 65 } //1 Client hook free failure
		$a_01_3 = {28 23 25 64 29 } //1 (#%d)
		$a_01_4 = {79 00 6b 00 74 00 73 00 74 00 61 00 72 00 } //1 yktstar
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}