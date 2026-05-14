
rule HackTool_BAT_SpoofPotato_A_AMTB{
	meta:
		description = "HackTool:BAT/SpoofPotato.A!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {53 70 6f 6f 66 65 64 20 74 61 72 67 65 74 } //Spoofed target  1
		$a_80_1 = {50 6f 74 61 74 6f 2e 70 64 62 } //Potato.pdb  1
		$a_80_2 = {50 6f 74 61 74 6f 2e 65 78 65 } //Potato.exe  1
		$a_80_3 = {53 74 61 72 74 69 6e 67 20 4e 42 4e 53 20 73 70 6f 6f 66 65 72 } //Starting NBNS spoofer  1
		$a_80_4 = {53 70 6f 6f 66 69 6e 67 20 77 70 61 64 } //Spoofing wpad  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}