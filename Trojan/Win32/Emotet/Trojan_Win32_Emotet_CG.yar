
rule Trojan_Win32_Emotet_CG{
	meta:
		description = "Trojan:Win32/Emotet.CG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 52 57 4a 65 72 68 57 45 23 2e 70 64 62 } //01 00  bRWJerhWE#.pdb
		$a_01_1 = {51 00 6c 00 6c 00 5a 00 64 00 2e 00 64 00 6c 00 6c 00 } //01 00  QllZd.dll
		$a_01_2 = {51 00 6c 00 6c 00 5a 00 61 00 64 00 } //00 00  QllZad
	condition:
		any of ($a_*)
 
}