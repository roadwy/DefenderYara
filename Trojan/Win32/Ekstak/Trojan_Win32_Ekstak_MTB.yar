
rule Trojan_Win32_Ekstak_MTB{
	meta:
		description = "Trojan:Win32/Ekstak!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c8 03 c3 46 8a 14 19 88 14 38 90 0a 20 00 8a 06 b9 90 01 04 a2 90 01 04 a1 90 01 04 03 c8 03 c3 46 8a 14 19 88 14 38 8a 83 90 01 04 84 c0 75 11 a1 90 01 04 8a 0d 90 01 04 03 c3 03 c7 30 08 83 3d 90 01 05 76 03 43 eb 06 e8 90 01 04 cf 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}