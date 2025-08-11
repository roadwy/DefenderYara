
rule Trojan_Win32_StealC_LJV_MTB{
	meta:
		description = "Trojan:Win32/StealC.LJV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff d6 8b f0 89 b4 24 a0 00 00 00 b2 78 c7 84 24 b0 00 00 00 78 19 1d 0b 33 c9 c7 84 24 b4 00 00 00 58 1d 0a 0a c7 84 24 b8 00 00 00 17 0a 42 58 c6 84 24 bc 00 00 00 00 8d 84 24 ?? ?? ?? ?? 30 14 08 41 83 f9 0b 73 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}