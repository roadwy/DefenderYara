
rule Ransom_Win32_Locky_MKV_MTB{
	meta:
		description = "Ransom:Win32/Locky.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c1 33 d2 f7 75 b4 8a 45 fe 02 c0 02 45 ff 89 4d ec 88 45 fe 01 15 90 01 04 ff d3 8b 4d f4 83 f1 7f ba 5e 7d f3 2a 83 e0 13 2b d1 0b c2 01 05 90 01 04 83 7d f4 00 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}