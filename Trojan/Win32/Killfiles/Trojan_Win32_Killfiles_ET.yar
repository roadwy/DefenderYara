
rule Trojan_Win32_Killfiles_ET{
	meta:
		description = "Trojan:Win32/Killfiles.ET,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 6e 61 74 69 76 65 32 5c 6f 62 6a 5c 69 33 38 36 5c 64 65 6c 69 63 69 6f 75 73 2e 70 64 62 } //01 00  \native2\obj\i386\delicious.pdb
		$a_01_1 = {4e 74 44 65 6c 65 74 65 46 69 6c 65 } //01 00  NtDeleteFile
		$a_01_2 = {4e 74 54 65 72 6d 69 6e 61 74 65 50 72 6f 63 65 73 73 } //01 00  NtTerminateProcess
		$a_01_3 = {47 00 62 00 50 00 6c 00 75 00 67 00 69 00 6e 00 5c 00 } //01 00  GbPlugin\
		$a_01_4 = {67 00 62 00 70 00 73 00 76 00 2e 00 65 00 78 00 65 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}