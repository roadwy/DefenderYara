
rule Trojan_Win32_UrSnif_RPD_MTB{
	meta:
		description = "Trojan:Win32/UrSnif.RPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 0f b6 c0 3a 4d 0f 75 22 8a 16 8b c8 23 c7 c1 e0 03 0f b6 d2 83 e1 1f 0b c2 46 0f b6 16 c1 e0 08 0b c2 46 05 08 08 00 00 eb 38 3a 4d fa 75 17 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}