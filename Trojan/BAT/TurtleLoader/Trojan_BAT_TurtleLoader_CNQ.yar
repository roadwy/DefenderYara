
rule Trojan_BAT_TurtleLoader_CNQ{
	meta:
		description = "Trojan:BAT/TurtleLoader.CNQ,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 61 6e 6f 6e 2e 51 75 69 63 6b 4d 65 6e 75 2e 55 74 69 6c 69 74 79 } //1 Canon.QuickMenu.Utility
		$a_01_1 = {43 4e 51 4d 55 54 49 4c } //1 CNQMUTIL
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}