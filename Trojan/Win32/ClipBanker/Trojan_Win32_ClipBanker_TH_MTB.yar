
rule Trojan_Win32_ClipBanker_TH_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.TH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 e6 51 b9 90 01 04 81 f1 90 01 04 81 c1 90 01 04 01 ce 59 81 c6 04 00 00 00 33 34 24 31 34 24 33 34 24 90 00 } //01 00 
		$a_03_1 = {89 e9 81 c1 04 00 00 00 89 ea 81 c2 90 01 04 81 32 90 01 04 89 ee 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}