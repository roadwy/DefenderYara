
rule Trojan_Win64_IcedID_AN_MTB{
	meta:
		description = "Trojan:Win64/IcedID.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 46 49 75 56 4d 46 61 57 } //01 00  CFIuVMFaW
		$a_01_1 = {46 4b 51 71 4b 6d 51 62 } //01 00  FKQqKmQb
		$a_01_2 = {48 65 6d 5a 6a 41 59 71 4b 69 } //01 00  HemZjAYqKi
		$a_01_3 = {4a 45 58 59 48 6a 48 65 42 } //01 00  JEXYHjHeB
		$a_01_4 = {50 6c 75 67 69 6e 49 6e 69 74 } //01 00  PluginInit
		$a_01_5 = {53 6c 6d 6c 61 68 77 59 } //00 00  SlmlahwY
	condition:
		any of ($a_*)
 
}