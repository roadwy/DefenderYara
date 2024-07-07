
rule Trojan_Win32_StarB{
	meta:
		description = "Trojan:Win32/StarB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 33 d2 f7 90 01 02 8b f2 8b c1 83 e0 01 85 c0 75 90 01 01 8b c1 8b 90 01 02 03 d1 32 02 8b d3 03 d1 88 02 eb 90 01 01 0f b6 90 01 02 8b d6 2a c2 8b 90 01 02 03 d1 32 02 8b d3 03 d1 88 02 03 90 01 02 0f b6 90 01 01 8b d3 03 d1 30 02 41 4f 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}