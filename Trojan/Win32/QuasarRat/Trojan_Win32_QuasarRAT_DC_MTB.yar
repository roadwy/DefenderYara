
rule Trojan_Win32_QuasarRAT_DC_MTB{
	meta:
		description = "Trojan:Win32/QuasarRAT.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 72 6f 63 65 73 73 20 61 6c 72 65 61 64 79 20 65 6c 65 76 61 74 65 64 2e } //1 Process already elevated.
		$a_01_1 = {67 65 74 5f 50 6f 74 65 6e 74 69 61 6c 6c 79 56 75 6c 6e 65 72 61 62 6c 65 50 61 73 73 77 6f 72 64 73 } //1 get_PotentiallyVulnerablePasswords
		$a_01_2 = {47 65 74 4b 65 79 6c 6f 67 67 65 72 4c 6f 67 73 44 69 72 65 63 74 6f 72 79 } //1 GetKeyloggerLogsDirectory
		$a_01_3 = {73 65 74 5f 50 6f 74 65 6e 74 69 61 6c 6c 79 56 75 6c 6e 65 72 61 62 6c 65 50 61 73 73 77 6f 72 64 73 } //1 set_PotentiallyVulnerablePasswords
		$a_01_4 = {42 51 75 61 73 61 72 2e 43 6c 69 65 6e 74 2e 45 78 74 65 6e 73 69 6f 6e 73 2e } //1 BQuasar.Client.Extensions.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}