
rule Trojan_BAT_AveMaria_NEDJ_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 04 00 00 "
		
	strings :
		$a_03_0 = {00 16 0a 2b 1b 00 7e ?? 00 00 04 06 7e ?? 00 00 04 06 91 20 ?? ?? 00 00 59 d2 9c 00 06 17 58 0a 06 7e ?? 00 00 04 8e 69 fe 04 0b 07 2d d7 7e ?? 00 00 04 0c 2b 00 08 2a } //10
		$a_01_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 66 00 69 00 6c 00 65 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 2e 00 69 00 6f 00 2f 00 64 00 61 00 74 00 61 00 2d 00 70 00 61 00 63 00 6b 00 61 00 67 00 65 00 2f 00 } //5 https://filetransfer.io/data-package/
		$a_01_2 = {53 79 73 74 65 6d 2e 57 69 6e 64 6f 77 73 2e 46 6f 72 6d 73 } //1 System.Windows.Forms
		$a_01_3 = {4b 4d 69 63 72 6f 73 6f 66 74 2e 56 69 73 75 61 6c 53 74 75 64 69 6f 2e 45 64 69 74 6f 72 73 2e 53 65 74 74 69 6e 67 73 44 65 73 69 67 6e 65 72 2e 53 65 74 74 69 6e 67 73 53 69 6e 67 6c 65 46 69 6c 65 47 65 6e 65 72 61 74 6f 72 } //1 KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=17
 
}