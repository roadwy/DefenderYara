
rule Trojan_Win32_Zonidel_VC_MTB{
	meta:
		description = "Trojan:Win32/Zonidel.VC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b cf 8b c7 c1 e9 90 01 01 03 4c 24 90 01 01 c1 e0 90 01 01 03 44 24 90 01 01 33 c8 8d 04 3b 33 c8 8b 44 24 90 01 01 2b f1 b9 90 01 04 2b c8 03 d9 4d 75 90 01 01 8b 6c 24 90 01 01 89 7d 90 01 01 5f 89 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}