
rule Trojan_BAT_TrojanProxy_AMTB{
	meta:
		description = "Trojan:BAT/TrojanProxy!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {57 65 6c 63 6f 6d 65 20 74 6f 20 57 65 62 50 72 6f 78 79 20 74 72 6f 6a 61 6e 20 70 72 6f 64 75 63 65 64 20 62 79 20 66 4c 61 53 68 } //Welcome to WebProxy trojan produced by fLaSh  1
		$a_80_1 = {2a 2a 20 54 72 6f 6a 61 6e 20 49 50 20 5b 4e 45 57 5d 3a } //** Trojan IP [NEW]:  1
		$a_80_2 = {54 72 6f 6a 61 6e 65 64 20 43 6c 69 65 6e 74 } //Trojaned Client  1
		$a_80_3 = {74 72 30 6a 34 6e 63 72 33 61 74 30 72 40 74 72 6f 6a 61 6e 2e 63 6f 6d } //tr0j4ncr3at0r@trojan.com  1
		$a_80_4 = {57 33 62 50 72 30 78 79 20 54 72 30 6a 34 6e 2e 70 64 62 } //W3bPr0xy Tr0j4n.pdb  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}