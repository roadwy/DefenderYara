
rule Trojan_Win64_KillMBR_ARAC_MTB{
	meta:
		description = "Trojan:Win64/KillMBR.ARAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {ff 15 42 4b 00 00 25 ff 00 00 80 7d 09 ff c8 0d 00 ff ff ff ff c0 88 84 1c 90 00 00 00 48 ff c3 48 81 fb 00 10 00 00 75 d7 } //3
		$a_00_1 = {5c 00 5c 00 2e 00 5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 44 00 72 00 69 00 76 00 65 00 } //2 \\.\PhysicalDrive
		$a_01_2 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 } //1 vssadmin delete shadows
		$a_01_3 = {72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 4e 6f } //1 recoveryenabled No
	condition:
		((#a_01_0  & 1)*3+(#a_00_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}