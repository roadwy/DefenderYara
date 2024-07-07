
rule Trojan_BAT_WarzoneRat_DB_MTB{
	meta:
		description = "Trojan:BAT/WarzoneRat.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {24 61 38 31 33 66 37 63 61 2d 36 35 62 37 2d 34 65 36 61 2d 62 65 65 33 2d 34 64 66 38 32 35 33 38 34 62 65 32 } //1 $a813f7ca-65b7-4e6a-bee3-4df825384be2
		$a_81_1 = {46 69 6c 65 52 65 70 6c 61 63 65 6d 65 6e 74 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 FileReplacement.My.Resources
		$a_81_2 = {46 69 6c 65 52 65 70 6c 61 63 65 6d 65 6e 74 2e 52 65 73 6f 75 72 63 65 73 } //1 FileReplacement.Resources
		$a_81_3 = {4e 65 75 74 72 61 6c 20 45 76 69 6c } //1 Neutral Evil
		$a_81_4 = {43 68 61 6f 74 69 63 20 45 76 69 6c } //1 Chaotic Evil
		$a_81_5 = {4c 61 77 66 75 6c 20 45 76 69 6c } //1 Lawful Evil
		$a_81_6 = {52 61 63 65 3a 20 47 6e 6f 6d 65 } //1 Race: Gnome
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}