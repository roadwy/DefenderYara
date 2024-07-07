
rule Backdoor_Win32_Zegost_ME{
	meta:
		description = "Backdoor:Win32/Zegost.ME,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {81 c3 58 9e 00 00 6a 01 53 ff d5 5f 5e 5d 5b c2 08 00 } //1
		$a_01_1 = {42 45 49 5a 48 55 } //1 BEIZHU
		$a_01_2 = {43 3a 5c 31 2e 74 6d 70 } //1 C:\1.tmp
		$a_01_3 = {5b 42 41 43 4b 53 50 41 43 45 5d } //1 [BACKSPACE]
		$a_01_4 = {5b 50 72 69 6e 74 20 53 63 72 65 65 6e 5d } //1 [Print Screen]
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}