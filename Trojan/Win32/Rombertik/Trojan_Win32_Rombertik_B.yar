
rule Trojan_Win32_Rombertik_B{
	meta:
		description = "Trojan:Win32/Rombertik.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 0e 89 08 66 8b 56 04 b9 90 01 04 2b ce 66 89 50 04 c6 06 e9 83 e9 05 89 4e 01 2b f0 83 ee 05 c6 40 06 e9 89 70 07 90 00 } //01 00 
		$a_01_1 = {84 d2 74 0b 83 7c 81 04 00 74 1b 84 d2 75 07 83 7c 81 04 00 75 10 40 83 f8 23 72 de } //01 00 
		$a_01_2 = {46 6f 72 6d 47 72 61 62 62 65 72 41 6c 65 78 48 46 2e 70 64 62 } //00 00  FormGrabberAlexHF.pdb
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}