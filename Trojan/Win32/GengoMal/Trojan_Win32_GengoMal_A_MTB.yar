
rule Trojan_Win32_GengoMal_A_MTB{
	meta:
		description = "Trojan:Win32/GengoMal.A!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {36 6d 33 57 65 59 68 58 41 53 74 5a 30 53 67 54 47 45 4e 51 2f 74 4e 39 4a 61 6a 76 56 66 64 39 74 44 36 32 34 47 6f 59 75 2f 31 65 33 6d 75 70 33 68 57 5f 5a 41 76 38 2d 42 37 59 58 4d 2f 64 6b 69 36 42 51 38 39 59 4c 74 33 45 48 31 50 68 4e 78 70 } //01 00 
		$a_01_1 = {47 6f 20 62 75 69 6c 64 20 49 44 } //00 00 
	condition:
		any of ($a_*)
 
}