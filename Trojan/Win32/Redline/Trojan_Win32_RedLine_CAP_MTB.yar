
rule Trojan_Win32_RedLine_CAP_MTB{
	meta:
		description = "Trojan:Win32/RedLine.CAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e2 c1 ea 06 8b c2 c1 e0 06 03 c2 8b d6 2b d0 0f b6 82 [0-04] b2 1c f6 ea 24 45 30 86 [0-04] 03 f3 81 fe 00 0c 02 00 0f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win32_RedLine_CAP_MTB_2{
	meta:
		description = "Trojan:Win32/RedLine.CAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 99 b9 41 00 00 00 f7 f9 8b 45 08 0f be 04 10 6b c0 ?? 99 b9 [0-04] f7 f9 8b 55 0c 03 55 fc 0f b6 0a 33 c8 8b 55 0c 03 55 fc 88 0a eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}