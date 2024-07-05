
rule Trojan_Win64_Dorifel_MKV_MTB{
	meta:
		description = "Trojan:Win64/Dorifel.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 e9 03 d1 c1 fa 05 8b c2 c1 e8 90 01 01 03 d0 0f be c2 6b d0 3a 0f b6 c1 2a c2 04 37 41 30 00 ff c1 4d 8d 40 01 83 f9 26 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}