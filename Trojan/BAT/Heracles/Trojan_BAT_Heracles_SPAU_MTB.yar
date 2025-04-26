
rule Trojan_BAT_Heracles_SPAU_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SPAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {08 06 07 6e 06 8e 69 6a 5d b7 91 d7 11 04 07 84 95 d7 6e 20 ff 00 00 00 6a 5f b8 0c } //3
		$a_01_1 = {57 69 6e 64 6f 77 73 41 70 70 31 32 2e 70 64 62 } //1 WindowsApp12.pdb
		$a_01_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}