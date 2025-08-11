
rule Trojan_BAT_Nekark_AYB_MTB{
	meta:
		description = "Trojan:BAT/Nekark.AYB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 49 43 61 6e 74 54 68 69 6e 6b 4f 66 41 4e 61 6d 65 4c 6d 61 6f 5c 6f 62 6a 5c 44 65 62 75 67 5c 49 43 61 6e 74 54 68 69 6e 6b 4f 66 41 4e 61 6d 65 4c 6d 61 6f 2e 70 64 62 } //2 \ICantThinkOfANameLmao\obj\Debug\ICantThinkOfANameLmao.pdb
		$a_00_1 = {61 00 61 00 61 00 5f 00 54 00 6f 00 75 00 63 00 68 00 4d 00 65 00 4e 00 6f 00 74 00 5f 00 2e 00 74 00 78 00 74 00 } //1 aaa_TouchMeNot_.txt
		$a_00_2 = {48 00 65 00 6c 00 6c 00 6f 00 20 00 62 00 79 00 20 00 72 00 75 00 6e 00 6e 00 69 00 6e 00 67 00 20 00 74 00 68 00 69 00 73 00 20 00 66 00 69 00 6c 00 65 00 20 00 79 00 6f 00 75 00 72 00 20 00 61 00 67 00 72 00 65 00 65 00 20 00 74 00 6f 00 20 00 73 00 6f 00 6d 00 65 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 6d 00 61 00 79 00 20 00 62 00 65 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 64 00 20 00 6f 00 72 00 20 00 6c 00 6f 00 73 00 74 00 } //1 Hello by running this file your agree to some files may be deleted or lost
		$a_00_3 = {4d 00 6f 00 76 00 69 00 6e 00 67 00 20 00 61 00 6e 00 64 00 20 00 68 00 69 00 64 00 69 00 6e 00 67 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 66 00 72 00 6f 00 6d 00 20 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 73 00 2e 00 2e 00 2e 00 } //1 Moving and hiding files from Documents...
		$a_01_4 = {4d 6f 76 65 41 6e 64 48 69 64 65 46 69 6c 65 73 } //1 MoveAndHideFiles
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}