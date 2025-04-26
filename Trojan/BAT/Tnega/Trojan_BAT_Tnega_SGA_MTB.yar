
rule Trojan_BAT_Tnega_SGA_MTB{
	meta:
		description = "Trojan:BAT/Tnega.SGA!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 69 64 65 4d 6f 64 75 6c 65 4e 61 6d 65 41 74 74 72 69 62 75 74 65 } //1 HideModuleNameAttribute
		$a_01_1 = {4d 79 2e 4d 79 50 72 6f 6a 65 63 74 2e 46 6f 72 6d 73 } //1 My.MyProject.Forms
		$a_01_2 = {24 31 38 33 30 62 37 30 33 2d 34 30 36 38 2d 34 30 39 34 2d 62 30 66 39 2d 36 64 34 35 36 62 36 66 37 65 38 36 } //1 $1830b703-4068-4094-b0f9-6d456b6f7e86
		$a_01_3 = {67 65 74 5f 52 65 71 75 65 73 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 get_RequestingAssembly
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}