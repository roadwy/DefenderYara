
rule TrojanDownloader_BAT_Heracles_AYA_MTB{
	meta:
		description = "TrojanDownloader:BAT/Heracles.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_00_0 = {53 00 6f 00 6c 00 61 00 72 00 61 00 2e 00 65 00 78 00 65 00 } //2 Solara.exe
		$a_00_1 = {54 00 68 00 69 00 73 00 20 00 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 72 00 65 00 71 00 75 00 69 00 72 00 65 00 73 00 20 00 61 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 69 00 76 00 65 00 20 00 70 00 72 00 69 00 76 00 69 00 6c 00 65 00 67 00 65 00 73 00 2e 00 } //1 This application requires administrative privileges.
		$a_00_2 = {2f 00 4f 00 62 00 75 00 66 00 73 00 63 00 61 00 74 00 65 00 64 00 2f 00 73 00 6f 00 6c 00 61 00 72 00 61 00 } //1 /Obufscated/solara
		$a_00_3 = {67 00 6f 00 74 00 20 00 72 00 61 00 74 00 74 00 65 00 64 00 20 00 6c 00 6d 00 61 00 6f 00 20 00 74 00 68 00 65 00 69 00 72 00 20 00 69 00 70 00 20 00 69 00 73 00 } //1 got ratted lmao their ip is
		$a_01_4 = {43 72 65 61 74 65 53 74 61 72 74 75 70 53 68 6f 72 74 63 75 74 } //1 CreateStartupShortcut
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}