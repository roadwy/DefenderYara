
rule Trojan_BAT_Anagra_R_MTB{
	meta:
		description = "Trojan:BAT/Anagra.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 61 73 6b 33 32 57 61 74 63 68 2e 70 64 62 } //1 Task32Watch.pdb
		$a_01_1 = {54 61 73 6b 33 32 57 61 74 63 68 2e 46 72 65 67 61 74 2e 72 65 73 6f 75 72 63 65 73 } //1 Task32Watch.Fregat.resources
		$a_01_2 = {53 00 68 00 65 00 6c 00 6c 00 20 00 49 00 6e 00 66 00 72 00 61 00 73 00 74 00 72 00 75 00 63 00 74 00 75 00 72 00 65 00 20 00 48 00 6f 00 73 00 74 00 } //1 Shell Infrastructure Host
		$a_01_3 = {44 00 4c 00 4c 00 20 00 48 00 6f 00 73 00 74 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 } //1 DLL Host Service
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}