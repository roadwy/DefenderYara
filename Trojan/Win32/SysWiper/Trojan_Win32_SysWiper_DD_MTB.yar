
rule Trojan_Win32_SysWiper_DD_MTB{
	meta:
		description = "Trojan:Win32/SysWiper.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_81_0 = {53 75 63 63 65 73 73 3a 20 4d 42 52 20 68 61 73 20 62 65 65 6e 20 6f 76 65 72 77 72 69 74 74 65 6e 21 } //10 Success: MBR has been overwritten!
		$a_81_1 = {2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 } //1 .\PhysicalDrive
		$a_81_2 = {46 61 69 6c 65 64 20 74 6f 20 6f 76 65 72 77 72 69 74 65 20 74 68 65 20 4d 42 52 } //1 Failed to overwrite the MBR
		$a_81_3 = {52 75 6e 20 61 73 20 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 } //1 Run as Administrator
		$a_81_4 = {55 6e 61 62 6c 65 20 74 6f 20 61 63 63 65 73 73 20 74 68 65 20 64 69 73 6b } //1 Unable to access the disk
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=14
 
}