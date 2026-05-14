
rule Trojan_BAT_Bobik_GMT_MTB{
	meta:
		description = "Trojan:BAT/Bobik.GMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {41 41 48 32 55 57 74 48 61 55 55 30 69 5f 33 4f 6d 78 4b 37 6d 7a 6d 52 4c 54 4b 38 4d 66 73 57 7a 53 6b } //AAH2UWtHaUU0i_3OmxK7mzmRLTK8MfsWzSk  1
		$a_80_1 = {61 70 69 2e 74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 } //api.telegram.org/bot  1
		$a_01_2 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 31 2e 70 64 62 } //1 WindowsFormsApp1.pdb
		$a_01_3 = {54 65 6c 65 67 72 61 6d 57 6f 72 6b 65 72 } //1 TelegramWorker
		$a_01_4 = {53 65 6e 64 54 6f 54 65 6c 65 67 72 61 6d } //1 SendToTelegram
		$a_80_5 = {2f 73 65 6e 64 44 6f 63 75 6d 65 6e 74 } ///sendDocument  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}