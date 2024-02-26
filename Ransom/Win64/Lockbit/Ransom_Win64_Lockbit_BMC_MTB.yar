
rule Ransom_Win64_Lockbit_BMC_MTB{
	meta:
		description = "Ransom:Win64/Lockbit.BMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 61 73 74 65 20 6e 6f 74 65 20 61 66 74 65 72 20 64 69 72 65 63 74 6f 72 79 20 63 68 61 6e 67 65 20 61 6e 64 20 65 6e 63 72 79 70 74 69 6f 6e 20 79 65 73 } //01 00  paste note after directory change and encryption yes
		$a_01_1 = {6b 69 6c 6c 20 6c 6f 6f 70 20 66 6f 72 20 74 61 73 6b 6d 67 72 2c 20 63 6d 64 2c 20 72 65 67 65 64 69 74 2c 20 70 6f 77 65 72 73 68 65 6c 6c 20 79 65 73 2f 6e 6f } //01 00  kill loop for taskmgr, cmd, regedit, powershell yes/no
		$a_01_2 = {72 65 62 6f 6f 74 20 61 66 74 65 72 20 65 6e 64 20 65 6e 63 72 79 70 74 69 6f 6e 20 6f 66 20 61 6c 6c 20 66 69 6c 65 73 20 6f 72 20 64 69 73 6b 73 20 79 65 73 2f 6e 6f } //00 00  reboot after end encryption of all files or disks yes/no
	condition:
		any of ($a_*)
 
}