
rule Trojan_BAT_Stealer_EM_MTB{
	meta:
		description = "Trojan:BAT/Stealer.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {4f 63 65 61 6e 2d 61 63 5f 50 72 6f 63 65 73 73 65 64 42 79 46 6f 64 79 } //1 Ocean-ac_ProcessedByFody
		$a_81_1 = {4f 63 65 61 6e 2d 61 63 2e 70 64 62 } //1 Ocean-ac.pdb
		$a_81_2 = {54 61 73 6b 6b 69 6c 6c 20 45 78 65 63 75 74 65 64 } //1 Taskkill Executed
		$a_81_3 = {6b 65 79 61 75 74 68 2e 77 69 6e } //1 keyauth.win
		$a_81_4 = {52 65 61 63 74 20 53 63 61 6e 6e 65 72 20 2d 20 43 68 65 61 74 } //1 React Scanner - Cheat
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}