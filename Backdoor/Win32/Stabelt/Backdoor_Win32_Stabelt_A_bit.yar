
rule Backdoor_Win32_Stabelt_A_bit{
	meta:
		description = "Backdoor:Win32/Stabelt.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_01_0 = {74 00 69 00 74 00 6c 00 65 00 2e 00 62 00 65 00 73 00 74 00 64 00 65 00 61 00 6c 00 73 00 2e 00 61 00 74 00 } //10 title.bestdeals.at
		$a_01_1 = {00 00 5c 00 6d 00 6d 00 74 00 61 00 73 00 6b 00 2e 00 65 00 78 00 65 00 } //1
		$a_01_2 = {4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 34 00 2e 00 30 00 } //1 Mozilla/4.0
		$a_01_3 = {63 6d 64 20 63 6f 6d 6d 61 6e 64 20 25 64 } //1 cmd command %d
		$a_01_4 = {67 75 61 64 61 6f 20 62 65 6e 67 20 6b 75 69 } //1 guadao beng kui
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=13
 
}