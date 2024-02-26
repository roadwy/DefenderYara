
rule Trojan_Win64_FeedLoad_A_dha{
	meta:
		description = "Trojan:Win64/FeedLoad.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 64 00 "
		
	strings :
		$a_03_0 = {85 c0 0f 88 90 01 04 c7 90 01 03 ef cd ab 89 c7 90 01 03 67 45 23 01 83 fd 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}