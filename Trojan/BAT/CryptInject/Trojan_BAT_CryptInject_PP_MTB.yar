
rule Trojan_BAT_CryptInject_PP_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.PP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {24 41 32 41 39 32 32 32 37 2d 45 37 44 30 2d 34 38 35 37 2d 42 30 35 38 2d 46 30 33 41 46 45 34 45 30 42 41 42 } //1 $A2A92227-E7D0-4857-B058-F03AFE4E0BAB
		$a_81_1 = {45 45 20 4d 6f 62 69 6c 65 20 47 61 6d 65 20 6f 66 20 74 68 65 20 59 65 61 72 } //1 EE Mobile Game of the Year
		$a_81_2 = {52 6f 62 6c 6f 78 20 43 6f 72 70 6f 72 61 74 69 6f 6e } //1 Roblox Corporation
		$a_81_3 = {52 6f 62 6c 6f 78 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Roblox.Properties.Resources
		$a_81_4 = {43 79 63 6c 65 5f 4a 75 6d 70 5f 47 61 6d 65 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //1 Cycle_Jump_Game.Form1.resources
		$a_81_5 = {67 65 74 5f 43 6f 6e 74 72 6f 6c 44 61 72 6b 44 61 72 6b } //1 get_ControlDarkDark
		$a_81_6 = {43 61 72 74 65 20 63 68 61 6e 63 65 20 3a 20 4c 61 20 42 61 6e 71 75 65 20 76 6f 75 73 20 64 6f 69 74 20 35 20 30 30 30 20 65 75 72 6f 73 2e } //1 Carte chance : La Banque vous doit 5 000 euros.
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}