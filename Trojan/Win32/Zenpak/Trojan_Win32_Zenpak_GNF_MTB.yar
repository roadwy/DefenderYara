
rule Trojan_Win32_Zenpak_GNF_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GNF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b ce 83 e1 1f 88 82 90 01 04 83 c6 03 0f b6 81 90 01 04 30 82 90 01 04 0f b6 82 90 01 04 2a 81 90 01 04 88 82 90 01 04 83 c2 03 81 fe 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}