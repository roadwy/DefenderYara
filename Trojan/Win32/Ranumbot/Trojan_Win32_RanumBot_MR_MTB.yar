
rule Trojan_Win32_RanumBot_MR_MTB{
	meta:
		description = "Trojan:Win32/RanumBot.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b f3 c1 e6 90 01 01 03 75 90 01 01 8b fb c1 ef 90 01 01 03 7d 90 01 01 03 d3 33 f2 81 3d 90 01 08 c7 05 90 01 08 75 90 01 01 8d 45 90 01 01 50 ff 15 90 01 04 33 fe 81 3d 90 01 08 75 90 01 01 6a 90 01 01 6a 90 01 01 6a 90 01 01 ff 15 90 01 04 8b 75 90 01 01 2b f7 81 3d 90 01 08 89 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}