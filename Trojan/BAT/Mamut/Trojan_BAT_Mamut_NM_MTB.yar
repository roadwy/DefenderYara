
rule Trojan_BAT_Mamut_NM_MTB{
	meta:
		description = "Trojan:BAT/Mamut.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 26 00 00 0a d0 ?? ?? ?? 1b 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 74 0e 00 } //5
		$a_01_1 = {50 61 63 6b 6d 61 6e } //1 Packman
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_Mamut_NM_MTB_2{
	meta:
		description = "Trojan:BAT/Mamut.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 72 69 76 61 74 65 20 53 70 6f 6f 66 65 72 20 62 79 20 4c 65 76 } //2 Private Spoofer by Lev
		$a_01_1 = {41 73 53 74 72 6f 6e 67 41 73 46 75 63 6b 20 6f 62 66 75 73 63 61 74 6f 72 20 62 79 20 43 68 61 72 74 65 72 } //2 AsStrongAsFuck obfuscator by Charter
		$a_01_2 = {4c 65 76 73 53 70 6f 6f 66 65 72 } //2 LevsSpoofer
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}