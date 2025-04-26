
rule Trojan_Win32_Ursnif_SA_MSR{
	meta:
		description = "Trojan:Win32/Ursnif.SA!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 00 69 00 6c 00 6c 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 20 00 73 00 61 00 66 00 65 00 } //1 Willprotect safe
		$a_01_1 = {62 72 6f 75 67 68 74 5c 73 69 67 6e 5c 66 69 6e 65 5c 6c 65 66 74 5c 63 65 6e 74 5c 62 65 6c 69 65 76 65 6e 69 67 68 74 2e 70 64 62 } //1 brought\sign\fine\left\cent\believenight.pdb
		$a_01_2 = {45 6e 74 65 72 43 72 69 74 69 63 61 6c 50 6f 6c 69 63 79 53 65 63 74 69 6f 6e } //1 EnterCriticalPolicySection
		$a_01_3 = {4d 69 63 72 6f 73 6f 66 74 2e 43 52 54 50 72 6f 76 69 64 65 72 } //1 Microsoft.CRTProvider
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}