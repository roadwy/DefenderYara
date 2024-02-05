
rule Trojan_Win32_Trickbot_KDP_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.KDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_02_0 = {58 5b b9 01 00 00 00 6b c9 00 c6 44 0d e4 90 01 01 50 53 90 00 } //02 00 
		$a_02_1 = {58 5b ba 01 00 00 00 c1 e2 00 c6 44 15 e4 90 01 01 50 53 90 00 } //02 00 
		$a_02_2 = {58 5b b8 01 00 00 00 d1 e0 c6 44 05 e4 90 01 01 50 53 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}