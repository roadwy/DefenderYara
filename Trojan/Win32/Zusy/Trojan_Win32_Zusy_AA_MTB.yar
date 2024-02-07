
rule Trojan_Win32_Zusy_AA_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {53 8b da c1 eb 90 01 01 8b 07 69 f6 90 01 04 69 c0 90 01 04 8b c8 c1 e9 90 01 01 33 c8 69 c9 95 e9 d1 5b 33 f1 83 ea 90 01 01 83 c7 90 01 01 4b 75 da 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zusy_AA_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {59 54 56 55 42 56 54 55 2e 44 4c 4c } //01 00  YTVUBVTU.DLL
		$a_01_1 = {48 63 66 79 76 67 4f 68 62 76 67 } //01 00  HcfyvgOhbvg
		$a_01_2 = {59 79 76 67 4b 62 75 76 67 79 } //01 00  YyvgKbuvgy
		$a_01_3 = {57 78 64 74 63 66 76 67 4f 6e 6a 6b 68 62 6a 67 } //00 00  WxdtcfvgOnjkhbjg
	condition:
		any of ($a_*)
 
}