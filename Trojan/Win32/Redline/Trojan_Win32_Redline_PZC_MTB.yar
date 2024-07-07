
rule Trojan_Win32_Redline_PZC_MTB{
	meta:
		description = "Trojan:Win32/Redline.PZC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 6a 00 ff 15 90 01 04 8b 44 24 28 01 44 24 14 8b 44 24 14 33 c3 33 44 24 10 c7 05 90 01 08 2b f0 8b ce c1 e1 04 89 44 24 14 89 4c 24 10 8b 44 24 2c 01 44 24 10 8b d6 c1 ea 05 03 d5 03 fe 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}