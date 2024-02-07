
rule Backdoor_Linux_Flosax_A_kext{
	meta:
		description = "Backdoor:Linux/Flosax.A!kext,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 70 70 6c 65 4f 73 61 78 } //01 00  appleOsax
		$a_01_1 = {2e 6b 65 78 74 2e 6d 63 68 6f 6f 6b } //01 00  .kext.mchook
		$a_01_2 = {61 70 70 6c 65 48 49 44 } //02 00  appleHID
		$a_01_3 = {2f 74 6d 70 2f 34 33 74 39 39 30 33 7a 7a } //02 00  /tmp/43t9903zz
		$a_01_4 = {83 f9 4f 7f 36 48 8d 51 01 80 3c 08 e8 75 ee 8b 74 08 01 8d 74 31 05 80 3c 30 55 75 e0 } //02 00 
		$a_01_5 = {83 fa 50 7d 24 8d 42 01 80 3c 11 e8 75 f0 8b 74 11 01 01 d6 80 7c 31 05 55 75 e3 } //00 00 
		$a_00_6 = {5d 04 00 } //00 7f 
	condition:
		any of ($a_*)
 
}