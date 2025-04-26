
rule Trojan_Win32_RemcosRAT_RPQ_MTB{
	meta:
		description = "Trojan:Win32/RemcosRAT.RPQ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {32 f8 03 c0 8b d0 0f b7 f0 35 1b 01 00 00 f7 c2 00 01 00 00 0f b7 c8 8b c6 0f 44 c8 d0 eb 0f b7 c1 75 d8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}