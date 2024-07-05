
rule Trojan_Win32_FrauDropper_NF_MTB{
	meta:
		description = "Trojan:Win32/FrauDropper.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {89 44 24 7c 66 8b 8c 24 90 01 04 66 89 8c 24 90 01 04 8b 84 24 9c 00 00 00 69 94 24 98 00 00 00 90 01 04 01 d0 8b 40 4c 89 84 24 90 01 04 8b 84 24 98 00 00 00 69 c0 90 00 } //03 00 
		$a_03_1 = {83 ec 0c 0f b7 84 24 90 01 04 09 c0 66 89 c6 66 89 b4 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}