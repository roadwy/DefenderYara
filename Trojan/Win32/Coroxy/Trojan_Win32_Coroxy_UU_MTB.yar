
rule Trojan_Win32_Coroxy_UU_MTB{
	meta:
		description = "Trojan:Win32/Coroxy.UU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {51 c7 04 24 90 01 04 8b 44 24 90 01 01 83 2c 24 04 01 04 24 8b 04 24 31 01 90 00 } //01 00 
		$a_03_1 = {8b d3 c1 ea 90 01 01 03 f3 c7 05 90 01 08 c7 05 90 01 08 89 54 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 81 3d 90 01 08 75 90 01 01 8d 44 24 90 01 01 50 68 90 01 04 ff 15 90 01 04 31 74 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 2b 7c 24 90 01 01 81 3d 90 01 08 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}