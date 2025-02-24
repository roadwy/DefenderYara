
rule Trojan_Win32_KillDisk_ARA_MTB{
	meta:
		description = "Trojan:Win32/KillDisk.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 53 48 4f 54 48 49 52 49 55 4d 2e 70 64 62 } //2 \SHOTHIRIUM.pdb
		$a_00_1 = {5c 00 5c 00 2e 00 5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 44 00 72 00 69 00 76 00 65 00 30 00 } //2 \\.\PhysicalDrive0
		$a_00_2 = {52 00 75 00 6e 00 20 00 6d 00 61 00 6c 00 77 00 61 00 72 00 65 00 } //2 Run malware
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}