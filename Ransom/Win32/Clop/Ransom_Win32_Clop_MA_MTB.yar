
rule Ransom_Win32_Clop_MA_MTB{
	meta:
		description = "Ransom:Win32/Clop.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 43 20 6e 65 74 20 73 74 6f 70 20 56 65 65 61 6d 44 65 70 6c 6f 79 6d 65 6e 74 53 65 72 76 69 63 65 20 2f 79 } //01 00  /C net stop VeeamDeploymentService /y
		$a_01_1 = {2f 43 20 6e 65 74 20 73 74 6f 70 20 53 73 74 70 53 76 63 20 2f 79 } //01 00  /C net stop SstpSvc /y
		$a_01_2 = {2f 43 20 6e 65 74 20 73 74 6f 70 20 56 65 65 61 6d 42 61 63 6b 75 70 53 76 63 20 2f 79 } //01 00  /C net stop VeeamBackupSvc /y
		$a_01_3 = {2f 43 20 76 73 73 61 64 6d 69 6e 20 72 65 73 69 7a 65 20 73 68 61 64 6f 77 73 74 6f 72 61 67 65 20 2f 66 6f 72 3d } //01 00  /C vssadmin resize shadowstorage /for=
		$a_01_4 = {52 00 45 00 41 00 44 00 4d 00 45 00 5f 00 52 00 45 00 41 00 44 00 4d 00 45 00 2e 00 74 00 78 00 74 00 } //00 00  README_README.txt
	condition:
		any of ($a_*)
 
}