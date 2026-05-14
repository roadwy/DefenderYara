
rule Trojan_BAT_RivatorStealer_A_AMTB{
	meta:
		description = "Trojan:BAT/RivatorStealer.A!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 07 00 00 "
		
	strings :
		$a_81_0 = {65 66 7a 65 65 7a 66 65 66 7a 65 66 72 2e 65 78 65 } //5 efzeezfefzefr.exe
		$a_81_1 = {52 49 56 41 54 4f 52 } //5 RIVATOR
		$a_03_2 = {74 00 65 00 6c 00 65 00 67 00 72 00 61 00 6d 00 2e 00 6f 00 72 00 67 00 2f 00 62 00 6f 00 74 00 [0-90] 73 00 65 00 6e 00 64 00 4d 00 65 00 73 00 73 00 61 00 67 00 65 00 } //5
		$a_03_3 = {74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 [0-90] 73 65 6e 64 4d 65 73 73 61 67 65 } //5
		$a_81_4 = {65 6e 63 72 79 70 74 65 64 5f 6b 65 79 } //1 encrypted_key
		$a_81_5 = {2a 2a 50 43 3a 2a 2a } //1 **PC:**
		$a_81_6 = {54 6f 6b 65 6e 73 3a } //1 Tokens:
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*5+(#a_03_2  & 1)*5+(#a_03_3  & 1)*5+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=17
 
}