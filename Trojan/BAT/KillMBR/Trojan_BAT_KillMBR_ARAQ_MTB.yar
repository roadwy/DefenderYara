
rule Trojan_BAT_KillMBR_ARAQ_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.ARAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 20 61 6d 20 76 69 72 75 73 21 20 46 75 63 6b 20 59 6f 75 } //2 I am virus! Fuck You
		$a_80_1 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //\\.\PhysicalDrive0  2
		$a_80_2 = {53 70 79 54 68 65 53 70 79 } //SpyTheSpy  2
		$a_80_3 = {46 75 63 6b 4d 42 52 } //FuckMBR  2
		$a_80_4 = {4d 42 52 20 4f 76 65 72 77 72 69 74 74 65 6e 2c 20 56 69 63 74 69 6d 20 72 65 62 6f 6f 74 65 64 } //MBR Overwritten, Victim rebooted  2
	condition:
		((#a_01_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2) >=10
 
}
rule Trojan_BAT_KillMBR_ARAQ_MTB_2{
	meta:
		description = "Trojan:BAT/KillMBR.ARAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 07 00 00 "
		
	strings :
		$a_01_0 = {72 65 67 5f 64 65 73 74 72 6f 79 } //2 reg_destroy
		$a_01_1 = {6d 62 72 5f 64 65 73 74 72 6f 79 } //2 mbr_destroy
		$a_01_2 = {4d 62 72 53 69 7a 65 } //2 MbrSize
		$a_80_3 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //\\.\PhysicalDrive0  1
		$a_80_4 = {2f 6b 20 72 65 67 20 64 65 6c 65 74 65 20 48 4b 43 52 20 2f 66 } ///k reg delete HKCR /f  3
		$a_00_5 = {47 44 49 5f 70 61 79 6c 6f 61 64 73 32 } //3 GDI_payloads2
		$a_80_6 = {63 6d 64 2e 65 78 65 } //cmd.exe  2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_80_3  & 1)*1+(#a_80_4  & 1)*3+(#a_00_5  & 1)*3+(#a_80_6  & 1)*2) >=15
 
}