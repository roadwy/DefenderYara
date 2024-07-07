
rule Trojan_Win32_Tnega_AC_MTB{
	meta:
		description = "Trojan:Win32/Tnega.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_00_0 = {31 45 fc 33 c5 50 89 65 e8 ff 75 f8 8b 45 fc c7 45 fc fe ff ff ff 89 45 f8 8d 45 f0 } //10
		$a_80_1 = {63 70 6c 75 73 70 6c 75 73 5f 6d 65 } //cplusplus_me  3
		$a_80_2 = {5c 70 61 79 6c 6f 61 64 64 6c 6c 5c 52 65 6c 65 61 73 65 5c 63 6d 64 2e 70 64 62 } //\payloaddll\Release\cmd.pdb  3
		$a_80_3 = {65 74 50 5a 4b 56 4a 56 5f 4d 65 6e 50 57 } //etPZKVJV_MenPW  3
		$a_80_4 = {4d 45 5f 41 44 41 75 64 69 74 2e 65 78 65 } //ME_ADAudit.exe  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=22
 
}