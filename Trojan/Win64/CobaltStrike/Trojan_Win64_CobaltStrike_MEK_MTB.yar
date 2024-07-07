
rule Trojan_Win64_CobaltStrike_MEK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MEK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 "
		
	strings :
		$a_81_0 = {74 70 73 3a 2f 2f 31 32 32 2e 32 32 38 2e 37 2e 32 32 35 2f 61 64 6d 69 6e 3f 66 69 6c 65 3d } //1 tps://122.228.7.225/admin?file=
		$a_81_1 = {43 61 63 68 65 20 53 65 73 73 69 6f 6e } //1 Cache Session
		$a_81_2 = {4e 65 74 77 6f 72 6b 4c 69 73 74 4d 61 6e 61 67 65 72 } //1 NetworkListManager
		$a_81_3 = {4b 65 72 62 65 72 6f 73 } //1 Kerberos
		$a_81_4 = {31 32 32 2e 31 39 33 2e 31 33 30 2e 37 34 } //1 122.193.130.74
		$a_81_5 = {6e 65 74 70 72 6f 66 6d 2c 6e 65 74 6d 61 6e } //1 netprofm,netman
		$a_81_6 = {65 70 6d 61 70 70 65 72 } //1 epmapper
		$a_81_7 = {53 65 63 75 72 69 74 79 3d 49 6d 70 65 72 73 6f 6e 61 74 69 6f 6e 20 44 79 6e 61 6d 69 63 20 46 61 6c 73 65 } //1 Security=Impersonation Dynamic False
		$a_81_8 = {31 32 31 2e 32 30 37 2e 32 32 39 2e 31 34 35 } //1 121.207.229.145
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=8
 
}