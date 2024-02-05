
rule Trojan_Win32_RelineStealer_VA_MTB{
	meta:
		description = "Trojan:Win32/RelineStealer.VA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8a 47 04 8d bf 90 01 04 88 02 f7 d9 d2 c9 81 ee 90 01 04 8b 0e 33 cb 90 00 } //0a 00 
		$a_01_1 = {d2 e4 8b 07 33 c3 f7 d0 48 f5 } //00 00 
	condition:
		any of ($a_*)
 
}