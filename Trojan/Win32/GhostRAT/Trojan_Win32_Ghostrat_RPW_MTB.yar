
rule Trojan_Win32_Ghostrat_RPW_MTB{
	meta:
		description = "Trojan:Win32/Ghostrat.RPW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 c6 45 ec 41 c6 45 ed 44 c6 45 ee 56 c6 45 ef 41 c6 45 f0 50 c6 45 f1 49 c6 45 f2 33 c6 45 f3 32 c6 45 f4 2e c6 45 f5 64 c6 45 f6 6c c6 45 f7 6c 88 5d f8 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}