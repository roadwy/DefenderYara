
rule Trojan_BAT_Starter_EB_MTB{
	meta:
		description = "Trojan:BAT/Starter.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_00_0 = {fa 25 33 00 16 00 00 01 00 00 00 06 00 00 00 02 00 00 00 01 00 00 00 05 00 00 00 04 00 00 00 01 00 00 00 02 } //10
		$a_80_1 = {45 3a 5c 24 4c 69 6d 65 55 53 42 5c 66 6f 74 6f } //E:\$LimeUSB\foto  3
		$a_80_2 = {45 3a 5c 24 4c 69 6d 65 55 53 42 5c 4c 69 6d 65 55 53 42 2e 65 78 65 } //E:\$LimeUSB\LimeUSB.exe  3
		$a_80_3 = {54 72 61 64 65 6d 61 72 6b 20 2d 20 4c 69 6d 65 } //Trademark - Lime  3
		$a_80_4 = {53 79 73 74 65 6d 2e 44 69 61 67 6e 6f 73 74 69 63 73 } //System.Diagnostics  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=22
 
}