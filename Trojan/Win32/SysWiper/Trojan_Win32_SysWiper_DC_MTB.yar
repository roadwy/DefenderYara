
rule Trojan_Win32_SysWiper_DC_MTB{
	meta:
		description = "Trojan:Win32/SysWiper.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_81_0 = {77 69 70 65 20 53 54 41 52 54 45 44 } //10 wipe STARTED
		$a_81_1 = {2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 } //1 .\PhysicalDrive
		$a_81_2 = {70 68 79 73 69 63 61 6c 20 64 72 69 76 65 20 77 69 6c 6c 20 62 65 20 6c 6f 73 74 } //1 physical drive will be lost
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=12
 
}