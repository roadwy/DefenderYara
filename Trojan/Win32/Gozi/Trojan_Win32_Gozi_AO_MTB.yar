
rule Trojan_Win32_Gozi_AO_MTB{
	meta:
		description = "Trojan:Win32/Gozi.AO!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 7d f4 8d 34 01 33 75 e0 83 e2 1f 33 75 e4 03 f2 56 51 8d 14 38 } //01 00 
		$a_01_1 = {33 c1 33 44 24 10 43 8a cb d3 c8 8b ce 89 02 83 c2 04 ff 4c 24 0c 75 e0 } //00 00 
	condition:
		any of ($a_*)
 
}