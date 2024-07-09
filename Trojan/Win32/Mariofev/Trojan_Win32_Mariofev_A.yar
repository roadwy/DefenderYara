
rule Trojan_Win32_Mariofev_A{
	meta:
		description = "Trojan:Win32/Mariofev.A,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 06 00 00 "
		
	strings :
		$a_00_0 = {8b 75 dc 59 53 57 56 6a 10 89 45 cc ff 15 } //10
		$a_02_1 = {6e 76 72 73 ?? 6c 33 32 2e 64 6c 6c } //2
		$a_00_2 = {70 20 69 20 6e 20 69 20 74 20 5f 20 64 20 6c 20 6c 20 73 } //2 p i n i t _ d l l s
		$a_00_3 = {70 61 73 6f 2e 65 6c } //2 paso.el
		$a_00_4 = {74 65 72 6d 73 72 76 2e 64 6c 6c 00 54 53 45 6e 61 62 6c 65 64 00 00 00 66 44 65 6e 79 54 53 43 6f 6e 6e 65 63 74 69 6f 6e 73 } //2
		$a_01_5 = {4e 74 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 NtQuerySystemInformation
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_01_5  & 1)*1) >=19
 
}