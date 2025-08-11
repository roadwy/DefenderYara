
rule Ransom_Win64_Nitrogen_A_MTB{
	meta:
		description = "Ransom:Win64/Nitrogen.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {54 61 6b 65 20 74 68 69 73 20 73 65 72 69 6f 75 73 6c 79 2c 20 74 68 69 73 20 69 73 20 6e 6f 74 20 61 20 6a 6f 6b 65 21 20 59 6f 75 72 20 63 6f 6d 70 61 6e 79 20 6e 65 74 77 6f 72 6b 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 20 61 6e 64 } //1 Take this seriously, this is not a joke! Your company network are encrypted and
		$a_81_1 = {79 6f 75 72 20 64 61 74 61 20 68 61 73 20 62 65 65 6e 20 73 74 6f 6c 65 6e 20 61 6e 64 20 64 6f 77 6e 6c 6f 61 64 65 64 20 74 6f 20 6f 75 72 20 73 65 72 76 65 72 73 2e 20 49 67 6e 6f 72 69 6e 67 20 74 68 69 73 20 6d 65 73 73 61 67 65 } //1 your data has been stolen and downloaded to our servers. Ignoring this message
		$a_81_2 = {2e 6f 6e 69 6f 6e } //1 .onion
		$a_81_3 = {49 6e 73 74 61 6c 6c 20 54 6f 72 20 42 72 6f 77 73 65 72 } //1 Install Tor Browser
		$a_81_4 = {5f 52 45 41 44 5f 4d 45 5f 2e 54 58 54 } //1 _READ_ME_.TXT
		$a_81_5 = {2e 4e 49 54 52 4f 47 45 4e } //1 .NITROGEN
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}