
rule Trojan_Win32_Zloader_FF_MTB{
	meta:
		description = "Trojan:Win32/Zloader.FF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 df c1 e1 04 03 c8 c1 e1 02 2b f9 03 d7 89 15 90 01 04 8b 44 24 14 2b d5 83 ea 08 81 c3 90 01 04 89 15 90 01 04 8b 54 24 10 89 1d 90 01 04 83 c2 04 89 18 8b 3d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}