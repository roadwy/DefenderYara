
rule Trojan_Win32_Gamaredon_psyY_MTB{
	meta:
		description = "Trojan:Win32/Gamaredon.psyY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {ba 03 c9 48 82 23 f1 ab a0 f1 23 71 8a d4 2f 51 a2 27 fd b3 77 ee 8c 43 b3 99 9f 61 f7 14 51 5c 71 e2 } //00 00 
	condition:
		any of ($a_*)
 
}