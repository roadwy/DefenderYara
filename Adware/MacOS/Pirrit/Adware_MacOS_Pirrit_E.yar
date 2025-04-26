
rule Adware_MacOS_Pirrit_E{
	meta:
		description = "Adware:MacOS/Pirrit.E,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6b 65 56 6f 42 4c 6e 6c } //1 keVoBLnl
		$a_01_1 = {7b 45 68 2e 63 31 64 } //1 {Eh.c1d
		$a_01_2 = {4b 42 35 65 4c 54 5c 54 } //1 KB5eLT\T
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}