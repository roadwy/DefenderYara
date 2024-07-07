
rule Trojan_Win64_QakBot_RPE_MTB{
	meta:
		description = "Trojan:Win64/QakBot.RPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 4e 6e 4e 4c 73 69 76 58 } //1 ANnNLsivX
		$a_01_1 = {42 4b 6f 30 6b 56 57 63 } //1 BKo0kVWc
		$a_01_2 = {42 54 39 79 52 35 74 61 } //1 BT9yR5ta
		$a_01_3 = {43 63 6d 4c 66 53 5a 6c } //1 CcmLfSZl
		$a_01_4 = {44 53 46 67 69 68 67 59 39 6a 70 } //1 DSFgihgY9jp
		$a_01_5 = {50 6c 75 67 69 6e 49 6e 69 74 } //1 PluginInit
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}