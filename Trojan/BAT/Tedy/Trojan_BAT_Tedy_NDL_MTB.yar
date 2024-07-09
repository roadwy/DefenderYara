
rule Trojan_BAT_Tedy_NDL_MTB{
	meta:
		description = "Trojan:BAT/Tedy.NDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {6f 69 00 00 0a 0b 07 03 16 03 8e 69 6f ?? 00 00 0a 0c 08 0d } //5
		$a_01_1 = {4d 79 53 71 6c 2e 49 6e 73 74 61 6c 6c 65 72 2e 4c 61 75 6e 63 68 65 72 2e 77 64 5f 54 35 65 6e 64 2e 72 65 73 6f 75 72 63 65 73 } //1 MySql.Installer.Launcher.wd_T5end.resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}