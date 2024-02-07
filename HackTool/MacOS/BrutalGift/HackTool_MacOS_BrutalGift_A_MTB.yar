
rule HackTool_MacOS_BrutalGift_A_MTB{
	meta:
		description = "HackTool:MacOS/BrutalGift.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {42 72 75 74 61 6c 20 47 69 66 74 } //01 00  Brutal Gift
		$a_00_1 = {70 61 67 65 73 70 65 72 73 6f 2d 6f 72 61 6e 67 65 2e 66 72 2f 64 63 68 6b 67 2f 69 6e 64 65 78 2e 68 74 6d 6c } //01 00  pagesperso-orange.fr/dchkg/index.html
		$a_00_2 = {61 74 74 61 63 6b 20 63 6f 6d 70 6c 65 74 65 64 } //01 00  attack completed
		$a_00_3 = {64 63 68 6b 67 2e 70 65 72 73 6f 2e 77 61 6e 61 64 6f 6f 2e 66 72 } //00 00  dchkg.perso.wanadoo.fr
		$a_00_4 = {5d 04 00 } //00 da 
	condition:
		any of ($a_*)
 
}