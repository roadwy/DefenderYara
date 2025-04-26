
rule Backdoor_BAT_Androm_KAAE_MTB{
	meta:
		description = "Backdoor:BAT/Androm.KAAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 00 36 00 2d 00 32 00 34 00 2d 00 31 00 35 00 2d 00 34 00 36 00 2d 00 31 00 34 00 2d 00 31 00 35 00 2d 00 37 00 34 00 2d } //1
		$a_01_1 = {4e 61 76 69 67 61 74 69 6f 6e 4c 69 62 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //1 NavigationLib.Form1.resources
		$a_01_2 = {53 74 72 69 6e 67 42 75 69 6c 64 65 72 } //1 StringBuilder
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}