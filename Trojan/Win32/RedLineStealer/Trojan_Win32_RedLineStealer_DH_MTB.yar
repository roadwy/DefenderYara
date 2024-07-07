
rule Trojan_Win32_RedLineStealer_DH_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b ce f7 e6 c1 ea 90 01 01 6b c2 90 01 01 2b c8 0f b6 81 90 01 04 8d 8f 90 01 04 30 86 90 01 04 03 ce b8 1f 85 eb 51 f7 e1 8b ce c1 ea 90 01 01 6b c2 90 01 01 2b c8 0f b6 81 90 01 04 30 86 90 01 04 83 c6 90 01 01 81 fe 7e 07 00 00 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}