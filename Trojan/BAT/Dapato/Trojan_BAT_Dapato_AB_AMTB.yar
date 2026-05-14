
rule Trojan_BAT_Dapato_AB_AMTB{
	meta:
		description = "Trojan:BAT/Dapato.AB!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_80_0 = {56 61 6e 69 6c 6c 61 52 61 74 53 74 75 62 } //VanillaRatStub  2
		$a_80_1 = {73 61 66 65 70 61 6c 2e 69 6e 2e 6e 65 74 } //safepal.in.net  1
		$a_80_2 = {4b 69 6c 6c 43 6c 69 65 6e 74 } //KillClient  1
		$a_80_3 = {70 75 72 65 65 61 74 73 2e 69 6e 2e 6e 65 74 } //pureeats.in.net  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=3
 
}