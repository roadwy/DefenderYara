
rule Trojan_Win32_Zenpak_GNZ_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GNZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {40 83 f0 09 42 40 01 2d 90 01 04 31 3d 90 01 04 8d 05 90 01 04 ff d0 83 f0 03 4a 89 1d 90 01 04 b8 90 01 04 83 f2 05 83 f0 03 01 35 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}