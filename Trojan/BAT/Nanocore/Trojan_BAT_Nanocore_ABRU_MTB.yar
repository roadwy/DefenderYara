
rule Trojan_BAT_Nanocore_ABRU_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABRU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 70 72 69 6e 67 50 65 6e 64 75 6c 75 6d 2e 53 70 72 69 6e 67 50 65 6e 64 75 6c 75 6d 2e 72 65 73 6f 75 72 63 65 73 } //3 SpringPendulum.SpringPendulum.resources
		$a_01_1 = {48 65 6c 6c 6f 57 50 46 41 70 70 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 HelloWPFApp.Properties.Resources.resources
		$a_01_2 = {48 65 6c 6c 6f 57 50 46 41 70 70 2e 50 72 6f 70 65 72 74 69 65 73 } //1 HelloWPFApp.Properties
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}