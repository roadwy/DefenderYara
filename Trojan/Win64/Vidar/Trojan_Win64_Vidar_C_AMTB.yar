
rule Trojan_Win64_Vidar_C_AMTB{
	meta:
		description = "Trojan:Win64/Vidar.C!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 "
		
	strings :
		$a_81_0 = {73 63 72 65 65 6e 73 68 6f 74 2e 6a 70 67 } //1 screenshot.jpg
		$a_81_1 = {55 73 65 4d 61 73 74 65 72 50 61 73 73 77 6f 72 64 } //1 UseMasterPassword
		$a_81_2 = {66 69 6c 65 73 5c 69 6e 66 6f 72 6d 61 74 69 6f 6e 2e 74 78 74 } //1 files\information.txt
		$a_81_3 = {70 61 73 73 77 6f 72 64 73 2e 74 78 74 } //1 passwords.txt
		$a_81_4 = {44 6f 77 6e 6c 6f 61 64 73 5c 25 73 5f 25 73 2e 74 78 74 } //1 Downloads\%s_%s.txt
		$a_81_5 = {57 61 6c 6c 65 74 73 } //1 Wallets
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=5
 
}