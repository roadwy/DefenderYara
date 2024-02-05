
rule Trojan_Win32_Stealc_GKJ_MTB{
	meta:
		description = "Trojan:Win32/Stealc.GKJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {2b c1 89 45 e8 69 c0 90 01 04 2b c1 66 89 45 ec 69 c0 90 01 04 2b c1 33 d2 69 c0 90 01 04 2b c1 88 44 15 f0 42 83 fa 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}