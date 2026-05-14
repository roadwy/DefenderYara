
rule HackTool_BAT_Flodder_AMTB{
	meta:
		description = "HackTool:BAT/Flodder!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {43 68 6f 6f 73 65 41 74 74 61 63 6b } //ChooseAttack  1
		$a_80_1 = {53 68 65 65 74 45 78 70 6c 6f 69 74 2e 45 78 70 6c 6f 69 74 73 } //SheetExploit.Exploits  1
		$a_80_2 = {53 70 6f 74 20 46 6c 6f 6f 64 } //Spot Flood  1
		$a_80_3 = {45 6e 74 65 72 20 70 61 74 68 20 66 6f 72 20 74 68 65 20 66 69 6c 65 2e 20 28 4e 4f 54 20 46 4f 4c 44 45 52 21 29 } //Enter path for the file. (NOT FOLDER!)  1
		$a_80_4 = {45 6e 74 65 72 20 68 77 69 64 20 66 6f 72 20 73 70 6f 6f 66 69 6e 67 2e } //Enter hwid for spoofing.  1
		$a_80_5 = {54 72 69 65 64 20 61 74 74 65 6d 70 74 20 74 6f 20 73 65 6e 64 20 70 61 63 6b 65 74 20 77 69 74 68 20 66 61 6b 65 20 75 73 65 72 2e } //Tried attempt to send packet with fake user.  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}