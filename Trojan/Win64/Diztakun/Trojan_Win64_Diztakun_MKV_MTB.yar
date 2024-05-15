
rule Trojan_Win64_Diztakun_MKV_MTB{
	meta:
		description = "Trojan:Win64/Diztakun.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 33 c0 8b c8 c1 e9 11 33 c8 b8 90 01 04 44 8b c1 41 c1 e0 05 44 33 c1 41 f7 e0 41 0f b7 c3 c1 ea 05 0f b7 ca 0f af c8 41 0f b7 c0 66 2b c1 66 83 c0 61 66 42 89 04 53 49 ff c2 4d 3b d1 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}