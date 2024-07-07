
rule Trojan_Linux_Mircforce_A_xp{
	meta:
		description = "Trojan:Linux/Mircforce.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {74 48 45 3a 6d 49 52 4b 66 4f 52 43 45 } //1 tHE:mIRKfORCE
		$a_01_1 = {73 2f 69 72 63 6e 65 74 2f 6d 69 72 6b 6e 65 74 2f } //2 s/ircnet/mirknet/
		$a_01_2 = {64 65 66 2e 66 6c 6f 6f 64 } //1 def.flood
		$a_01_3 = {52 41 57 20 69 52 43 4c 69 4e 45 } //1 RAW iRCLiNE
		$a_01_4 = {2e 3a 74 48 61 20 6c 45 45 74 66 30 72 43 65 3a 2e } //1 .:tHa lEEtf0rCe:.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}