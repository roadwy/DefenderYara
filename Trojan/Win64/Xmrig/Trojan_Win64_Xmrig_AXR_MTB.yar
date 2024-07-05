
rule Trojan_Win64_Xmrig_AXR_MTB{
	meta:
		description = "Trojan:Win64/Xmrig.AXR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 c0 48 8b 5c 24 48 48 8b 4c 24 30 48 8d 3d c9 e1 07 00 be 18 00 00 00 e8 d9 4e df ff 48 89 44 24 58 48 89 5c 24 40 48 8b 4c 24 30 48 8d 3d b2 cd 07 00 be 16 00 00 00 31 c0 48 8b 5c 24 48 e8 b2 4e df ff 48 89 44 24 50 48 89 5c 24 38 48 89 c1 48 89 df 48 8d 05 b4 44 08 00 } //00 00 
	condition:
		any of ($a_*)
 
}