
rule Trojan_Win32_SentryTome_A_dha{
	meta:
		description = "Trojan:Win32/SentryTome.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {ee c6 44 24 90 01 01 c1 90 02 04 c6 44 24 90 01 01 c4 90 02 04 c6 44 24 90 01 01 87 90 02 04 c6 44 24 90 01 01 a9 90 02 04 c6 44 24 90 01 01 f0 90 00 } //01 00 
		$a_02_1 = {fd c6 44 24 90 01 01 5b 90 02 04 c6 44 24 90 01 01 84 90 02 04 c6 44 24 90 01 01 3a 90 02 04 c6 44 24 90 01 01 12 90 02 04 c6 44 24 90 01 01 d0 90 00 } //01 00 
		$a_02_2 = {d0 c6 44 24 90 01 01 cd 90 02 09 c6 44 24 90 01 01 58 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}