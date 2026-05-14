
rule Trojan_BAT_XWorm_AMTB{
	meta:
		description = "Trojan:BAT/XWorm!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {3c 47 61 6c 61 78 79 52 41 54 3e } //<GalaxyRAT>  1
		$a_80_1 = {4d 79 43 6f 6d 70 75 74 65 72 7c 2e 2e 7c 42 61 63 6b } //MyComputer|..|Back  1
		$a_80_2 = {4d 79 43 6f 6d 70 75 74 65 72 7c 4d 79 43 6f 6d 70 75 74 65 72 7c 43 75 72 72 65 6e 74 } //MyComputer|MyComputer|Current  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}