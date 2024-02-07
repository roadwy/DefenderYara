
rule Trojan_Win32_Unfender_A{
	meta:
		description = "Trojan:Win32/Unfender.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 79 76 6d 68 76 74 67 65 69 5c 62 6d 6a 63 5c 66 65 65 2e 70 64 62 } //01 00  oyvmhvtgei\bmjc\fee.pdb
		$a_01_1 = {69 74 27 73 20 69 6e 66 65 63 74 65 64 20 62 79 20 61 20 56 69 72 75 73 20 6f 72 20 63 72 61 63 6b 65 64 2e 20 54 68 69 73 20 66 69 6c 65 20 77 6f 6e 27 74 20 77 6f 72 6b 20 61 6e 79 6d 6f 72 65 2e } //01 00  it's infected by a Virus or cracked. This file won't work anymore.
		$a_01_2 = {44 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 } //01 00  Defender Software
		$a_01_3 = {41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 } //00 00  Antivirus Software
	condition:
		any of ($a_*)
 
}