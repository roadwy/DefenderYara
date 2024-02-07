
rule Backdoor_Linux_Gafgyt_BA_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.BA!xp,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {64 72 65 61 6d 62 6f 78 } //02 00  dreambox
		$a_01_1 = {78 6d 68 64 69 70 63 } //01 00  xmhdipc
		$a_01_2 = {61 64 6d 69 6e 31 32 33 34 } //01 00  admin1234
		$a_01_3 = {6b 6c 76 31 32 33 } //00 00  klv123
	condition:
		any of ($a_*)
 
}