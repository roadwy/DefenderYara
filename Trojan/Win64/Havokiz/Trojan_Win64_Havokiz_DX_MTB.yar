
rule Trojan_Win64_Havokiz_DX_MTB{
	meta:
		description = "Trojan:Win64/Havokiz.DX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 94 03 f0 00 00 00 80 fa ff 75 10 c6 84 03 f0 00 00 00 00 48 83 e8 01 73 e6 eb 0b 48 98 ff c2 88 94 03 f0 00 00 00 31 c0 48 63 d0 ff c0 8a 54 14 30 30 16 48 ff c6 e9 } //01 00 
		$a_01_1 = {45 31 d1 44 32 52 ff 41 31 c1 89 c8 01 c9 c0 e8 07 45 31 c8 0f af c7 44 88 42 fe 45 89 d0 44 31 c0 31 c1 88 4a ff 49 39 d3 0f 85 } //00 00 
	condition:
		any of ($a_*)
 
}