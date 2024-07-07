
rule Trojan_BAT_KillMBR_ARBH_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.ARBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 42 52 5f 6f 76 65 72 77 72 69 74 65 72 } //2 MBR_overwriter
		$a_80_1 = {6d 62 72 20 64 65 73 74 72 6f 79 65 64 } //mbr destroyed  2
		$a_80_2 = {2f 6b 20 72 65 67 20 64 65 6c 65 74 65 20 48 4b 43 52 20 2f 66 } ///k reg delete HKCR /f  2
		$a_80_3 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //\\.\PhysicalDrive0  2
		$a_80_4 = {3f 57 68 65 72 65 20 61 6d 20 49 } //?Where am I  2
	condition:
		((#a_01_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2) >=10
 
}