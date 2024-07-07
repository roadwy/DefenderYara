
rule Trojan_BAT_KillMBR_ARBE_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.ARBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 42 52 20 52 65 77 72 69 74 74 65 6e 20 4c 4f 4c } //2 MBR Rewritten LOL
		$a_80_1 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //\\.\PhysicalDrive0  2
		$a_80_2 = {56 4d 77 61 72 65 7c 56 49 52 54 55 41 4c 7c 41 20 4d 20 49 7c 58 65 6e } //VMware|VIRTUAL|A M I|Xen  2
		$a_80_3 = {73 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 57 69 6e 33 32 5f 42 49 4f 53 } //select * from Win32_BIOS  2
		$a_80_4 = {73 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 57 69 6e 33 32 5f 43 6f 6d 70 75 74 65 72 53 79 73 74 65 6d } //select * from Win32_ComputerSystem  2
	condition:
		((#a_01_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2) >=10
 
}