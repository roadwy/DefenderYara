
rule Trojan_Win32_Nitol_RF_MTB{
	meta:
		description = "Trojan:Win32/Nitol.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 6f 63 75 6d 65 6e 74 73 5c 75 70 64 61 74 65 2e 6c 6e 6b } //1 Documents\update.lnk
		$a_01_1 = {42 65 6e 73 6f 6e 73 2e 70 64 62 } //1 Bensons.pdb
		$a_01_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 64 00 65 00 70 00 61 00 72 00 74 00 6d 00 65 00 6e 00 74 00 2e 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 6d 00 69 00 64 00 64 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 2e 00 74 00 6b 00 } //2 http://department.microsoftmiddlename.tk
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=4
 
}