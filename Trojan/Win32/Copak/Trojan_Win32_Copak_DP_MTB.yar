
rule Trojan_Win32_Copak_DP_MTB{
	meta:
		description = "Trojan:Win32/Copak.DP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {83 ec 04 89 14 24 8b 34 24 83 c4 04 31 3b 89 f6 be ca ac 7f fe 43 39 c3 75 } //02 00 
		$a_01_1 = {83 c4 04 81 c3 ba fe 0a e5 46 81 ea dc a0 ae 39 68 5f b4 1b 06 5a 01 d2 81 fe c2 5f 00 01 75 } //00 00 
	condition:
		any of ($a_*)
 
}