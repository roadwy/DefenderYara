
rule Backdoor_Win32_Weniavera_A{
	meta:
		description = "Backdoor:Win32/Weniavera.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 "
		
	strings :
		$a_01_0 = {65 78 65 20 2f 63 20 00 } //5
		$a_01_1 = {57 45 4e 21 00 } //1
		$a_01_2 = {2e 2e 2e 3b 3b 2e 2e 00 } //1 ⸮㬮⸻.
		$a_01_3 = {2e 2e 2e 2e 7c 2e 2e 00 } //1
		$a_01_4 = {2e 2e 2e 24 2e 2e 2e 00 } //1
		$a_01_5 = {2e 2e 2e 2e 3f 2f 2e 00 } //1 ⸮⸮⼿.
		$a_01_6 = {21 21 2c 40 2c 5f 28 29 5b 5d 2e 2e 3b 21 00 } //1
		$a_00_7 = {68 bb 01 00 00 89 84 24 98 00 00 00 ff d7 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_00_7  & 1)*1) >=10
 
}