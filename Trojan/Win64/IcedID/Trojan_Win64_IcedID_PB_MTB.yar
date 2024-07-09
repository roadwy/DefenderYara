
rule Trojan_Win64_IcedID_PB_MTB{
	meta:
		description = "Trojan:Win64/IcedID.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 89 c0 4c 03 45 d0 8b 45 dc 48 98 48 03 45 20 44 0f b6 08 8b 4d dc ba ?? ?? ?? ?? 89 c8 f7 ea c1 fa 03 89 c8 c1 f8 1f 89 d3 29 c3 89 d8 6b c0 3b 89 ca 29 c2 89 d0 48 98 48 03 45 c8 0f b6 00 44 31 c8 41 88 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}