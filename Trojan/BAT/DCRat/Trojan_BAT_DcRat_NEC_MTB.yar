
rule Trojan_BAT_DcRat_NEC_MTB{
	meta:
		description = "Trojan:BAT/DcRat.NEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {6f e8 00 00 0a 74 07 00 00 01 1a 1b 1f 16 73 98 01 00 0a 6f 09 00 00 0a 28 2a 04 00 06 00 02 } //03 00 
		$a_01_1 = {6b 4c 6a 77 34 69 49 73 43 4c 73 5a 74 78 63 34 6c 6b 73 4e 30 6a } //01 00  kLjw4iIsCLsZtxc4lksN0j
		$a_01_2 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //01 00  GetExecutingAssembly
		$a_01_3 = {67 65 74 5f 50 72 6f 63 65 73 73 4e 61 6d 65 } //01 00  get_ProcessName
		$a_01_4 = {24 24 6d 65 74 68 6f 64 30 78 36 30 30 30 30 35 66 2d 31 } //01 00  $$method0x600005f-1
		$a_01_5 = {67 65 74 5f 49 73 36 34 42 69 74 4f 70 65 72 61 74 69 6e 67 53 79 73 74 65 6d } //00 00  get_Is64BitOperatingSystem
	condition:
		any of ($a_*)
 
}