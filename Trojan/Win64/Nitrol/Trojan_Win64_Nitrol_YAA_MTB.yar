
rule Trojan_Win64_Nitrol_YAA_MTB{
	meta:
		description = "Trojan:Win64/Nitrol.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 03 00 00 "
		
	strings :
		$a_03_0 = {66 0f 1f 44 00 00 48 8b 05 ?? ?? ?? ?? 31 14 03 48 83 c3 04 8b 05 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 15 } //10
		$a_01_1 = {50 4d 6a 55 4d 57 46 61 6b } //4 PMjUMWFak
		$a_01_2 = {6e 4a 6c 51 77 78 70 6a 52 42 51 58 } //4 nJlQwxpjRBQX
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4) >=18
 
}