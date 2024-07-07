
rule Trojan_Win64_Dridex_EB_MTB{
	meta:
		description = "Trojan:Win64/Dridex.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_81_0 = {68 46 6f 66 75 70 64 61 74 65 73 69 6e 74 6f } //3 hFofupdatesinto
		$a_81_1 = {44 76 2e 32 39 63 68 61 6e 6e 65 6c 3b } //3 Dv.29channel;
		$a_81_2 = {46 47 54 52 59 59 42 2e 70 64 62 } //3 FGTRYYB.pdb
		$a_81_3 = {57 69 6e 74 72 75 73 74 52 65 6d 6f 76 65 41 63 74 69 6f 6e 49 44 } //3 WintrustRemoveActionID
		$a_81_4 = {43 72 79 70 74 47 65 74 44 65 66 61 75 6c 74 50 72 6f 76 69 64 65 72 57 } //3 CryptGetDefaultProviderW
		$a_81_5 = {43 72 65 61 74 65 53 63 61 6c 61 62 6c 65 46 6f 6e 74 52 65 73 6f 75 72 63 65 41 } //3 CreateScalableFontResourceA
		$a_81_6 = {2e 75 73 65 64 56 79 54 68 65 4d 4c 69 6e } //3 .usedVyTheMLin
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3) >=21
 
}