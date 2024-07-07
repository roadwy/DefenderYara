
rule Trojan_AndroidOS_Fakecalls_M{
	meta:
		description = "Trojan:AndroidOS/Fakecalls.M,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 75 68 33 54 51 70 6d 4e 44 65 4f 57 5a 4d 73 49 79 39 37 2b } //1 Euh3TQpmNDeOWZMsIy97+
		$a_01_1 = {41 50 4b 20 44 6f 77 6e 6c 6f 61 64 20 46 61 69 6c 65 64 20 64 6f 49 6e 42 61 63 6b 67 72 6f 75 6e 64 20 63 61 74 63 68 } //1 APK Download Failed doInBackground catch
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_AndroidOS_Fakecalls_M_2{
	meta:
		description = "Trojan:AndroidOS/Fakecalls.M,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 68 65 63 6b 57 68 6f 57 68 6f 53 74 61 74 75 73 } //2 checkWhoWhoStatus
		$a_01_1 = {69 73 49 6e 73 74 61 6c 6c 65 64 57 68 6f 57 68 6f } //2 isInstalledWhoWho
		$a_01_2 = {72 75 6e 57 68 6f 57 68 6f } //2 runWhoWho
		$a_01_3 = {72 65 71 75 65 73 74 49 6e 73 74 61 6c 6c 55 6e 6b 6e 6f 77 6e 41 70 70 } //2 requestInstallUnknownApp
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}