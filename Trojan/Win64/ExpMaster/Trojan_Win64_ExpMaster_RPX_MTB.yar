
rule Trojan_Win64_ExpMaster_RPX_MTB{
	meta:
		description = "Trojan:Win64/ExpMaster.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 72 6f 67 72 61 6d 44 61 74 61 5c 5c 31 2e 62 61 74 } //01 00  ProgramData\\1.bat
		$a_01_1 = {53 77 61 70 69 6e 67 20 73 68 65 6c 6c 2e } //01 00  Swaping shell.
		$a_01_2 = {41 75 74 68 6f 72 3a 20 53 42 53 42 } //01 00  Author: SBSB
		$a_01_3 = {4b 33 32 45 6e 75 6d 44 65 76 69 63 65 44 72 69 76 65 72 73 } //01 00  K32EnumDeviceDrivers
		$a_01_4 = {4d 61 79 62 65 20 70 61 74 63 68 65 64 21 } //01 00  Maybe patched!
		$a_01_5 = {43 56 45 2d 32 30 31 38 2d 38 36 33 39 2d 65 78 70 2d 6d 61 73 74 65 72 } //01 00  CVE-2018-8639-exp-master
		$a_01_6 = {65 78 70 2e 70 64 62 } //01 00  exp.pdb
		$a_01_7 = {54 72 69 67 67 65 72 20 76 75 6c 2e } //01 00  Trigger vul.
		$a_01_8 = {45 6e 75 6d 44 65 76 69 63 65 44 72 69 76 65 72 73 } //00 00  EnumDeviceDrivers
	condition:
		any of ($a_*)
 
}