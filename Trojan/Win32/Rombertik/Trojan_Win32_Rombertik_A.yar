
rule Trojan_Win32_Rombertik_A{
	meta:
		description = "Trojan:Win32/Rombertik.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {74 30 8b 16 89 10 8a 4e 04 ba 90 01 04 2b d6 88 48 04 c6 06 e9 83 ea 05 89 56 01 2b f0 83 ee 05 89 70 06 c6 40 05 e9 90 00 } //01 00 
		$a_01_1 = {84 d2 74 0b 83 7c 81 04 00 74 1b 84 d2 75 07 83 7c 81 04 00 75 10 40 83 f8 23 72 de } //01 00 
		$a_01_2 = {2f 65 6d 65 2f 30 33 2f 69 6e 64 65 78 2e 70 68 70 3f 61 3d 69 6e 73 65 72 74 } //01 00  /eme/03/index.php?a=insert
		$a_01_3 = {46 6f 72 6d 47 72 61 62 62 65 72 4b 69 74 2e 70 64 62 } //00 00  FormGrabberKit.pdb
	condition:
		any of ($a_*)
 
}