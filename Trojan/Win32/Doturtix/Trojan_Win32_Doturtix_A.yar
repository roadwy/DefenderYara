
rule Trojan_Win32_Doturtix_A{
	meta:
		description = "Trojan:Win32/Doturtix.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 78 65 63 75 74 65 46 69 6c 65 00 } //01 00  硅捥瑵䙥汩e
		$a_01_1 = {64 65 6c 65 74 65 73 65 6c 66 2e 62 61 74 00 } //01 00 
		$a_01_2 = {61 54 68 69 73 44 6c 6c 46 69 6c 65 3a } //01 00  aThisDllFile:
		$a_01_3 = {61 45 78 65 63 75 74 65 46 69 6c 65 3a } //01 00  aExecuteFile:
		$a_01_4 = {2e 2e 2e 52 55 4e 3a 3a } //00 00  ...RUN::
	condition:
		any of ($a_*)
 
}