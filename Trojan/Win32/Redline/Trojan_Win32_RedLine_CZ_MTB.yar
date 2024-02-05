
rule Trojan_Win32_RedLine_CZ_MTB{
	meta:
		description = "Trojan:Win32/RedLine.CZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {8a 84 3c 10 01 00 00 88 84 34 10 01 00 00 88 8c 3c 10 01 00 00 0f b6 84 34 10 01 00 00 03 c2 0f b6 c0 8a 84 04 10 01 00 00 30 83 70 3a 43 00 43 81 fb 90 01 04 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}