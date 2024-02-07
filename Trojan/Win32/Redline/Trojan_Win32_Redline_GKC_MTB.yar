
rule Trojan_Win32_Redline_GKC_MTB{
	meta:
		description = "Trojan:Win32/Redline.GKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {89 d8 31 d2 f7 75 14 8b 45 08 0f be 04 10 69 c0 d6 cc e1 c2 30 04 1e 43 eb d1 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00  VirtualProtect
	condition:
		any of ($a_*)
 
}