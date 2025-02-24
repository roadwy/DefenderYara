
rule Trojan_Win32_PovertyStealer_APV_MTB{
	meta:
		description = "Trojan:Win32/PovertyStealer.APV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b ca c1 f9 06 83 e2 3f 6b d2 38 8b 0c 8d 08 4e 42 00 88 44 11 29 8b 0b 8b c1 c1 f8 06 83 e1 3f 6b d1 38 8b 0c 85 08 4e 42 00 8b 45 14 c1 e8 10 32 44 11 2d 24 01 30 44 11 2d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}