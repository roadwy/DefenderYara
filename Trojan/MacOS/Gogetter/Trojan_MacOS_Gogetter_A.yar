
rule Trojan_MacOS_Gogetter_A{
	meta:
		description = "Trojan:MacOS/Gogetter.A,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 62 69 6e 2f 62 61 73 68 } //01 00  /bin/bash
		$a_03_1 = {68 74 74 70 3a 2f 2f 61 70 69 2e 90 02 0f 2e 63 6f 6d 2f 67 61 3f 61 3d 25 73 26 62 3d 25 73 90 00 } //01 00 
		$a_01_2 = {49 4f 50 6c 61 74 66 6f 72 6d 45 78 70 65 72 74 44 65 76 69 63 65 } //01 00  IOPlatformExpertDevice
		$a_01_3 = {2f 74 6d 70 30 78 25 78 31 30 38 30 33 31 32 35 } //00 00  /tmp0x%x10803125
	condition:
		any of ($a_*)
 
}