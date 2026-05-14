
rule Trojan_BAT_SpyGate_AA_AMTB{
	meta:
		description = "Trojan:BAT/SpyGate.AA!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {48 32 31 20 28 68 32 31 40 65 78 70 6c 6f 69 74 2e 69 6d 29 } //H21 (h21@exploit.im)  1
		$a_80_1 = {68 32 31 72 64 70 68 76 6e 63 2e 70 64 62 } //h21rdphvnc.pdb  1
		$a_80_2 = {35 2e 38 2e 38 38 2e 32 33 33 } //5.8.88.233  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}