
rule Trojan_Win64_IcedID_AJ_MTB{
	meta:
		description = "Trojan:Win64/IcedID.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 63 56 6e 65 56 68 48 6c 65 7a } //01 00  AcVneVhHlez
		$a_01_1 = {41 6a 77 54 4a 66 4a 75 } //01 00  AjwTJfJu
		$a_01_2 = {44 61 45 6d 4b 62 43 } //01 00  DaEmKbC
		$a_01_3 = {44 66 55 4b 79 45 74 65 53 } //01 00  DfUKyEteS
		$a_01_4 = {50 6c 75 67 69 6e 49 6e 69 74 } //00 00  PluginInit
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_AJ_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {41 59 37 78 70 51 } //02 00  AY7xpQ
		$a_01_1 = {41 65 34 75 4a 67 } //02 00  Ae4uJg
		$a_01_2 = {42 32 41 67 61 6b 6b 4e 38 } //02 00  B2AgakkN8
		$a_01_3 = {42 33 33 44 43 46 73 31 } //02 00  B33DCFs1
		$a_01_4 = {42 48 6f 33 4a 75 6d 47 6e } //02 00  BHo3JumGn
		$a_01_5 = {42 59 57 31 52 37 57 55 65 34 31 } //00 00  BYW1R7WUe41
	condition:
		any of ($a_*)
 
}