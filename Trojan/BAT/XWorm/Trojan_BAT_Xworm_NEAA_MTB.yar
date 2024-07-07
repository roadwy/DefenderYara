
rule Trojan_BAT_Xworm_NEAA_MTB{
	meta:
		description = "Trojan:BAT/Xworm.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {24 38 32 66 66 35 65 35 35 2d 39 34 66 30 2d 34 35 33 30 2d 62 39 32 38 2d 37 64 65 61 62 61 31 63 64 66 33 37 } //5 $82ff5e55-94f0-4530-b928-7deaba1cdf37
		$a_01_1 = {67 65 74 5f 48 61 72 64 77 61 72 65 4c 6f 63 6b 5f 42 49 4f 53 } //1 get_HardwareLock_BIOS
		$a_01_2 = {47 65 74 50 72 6f 63 65 73 73 65 73 42 79 4e 61 6d 65 } //1 GetProcessesByName
		$a_01_3 = {49 6e 74 65 6c 6c 69 4c 6f 63 6b 2e 4c 69 63 65 6e 73 69 6e 67 } //1 IntelliLock.Licensing
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}