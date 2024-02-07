
rule Trojan_Win32_FakeAv_CC_MTB{
	meta:
		description = "Trojan:Win32/FakeAv.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 f6 33 c0 8a 82 90 02 04 33 c8 8b 15 90 02 04 03 15 90 02 04 88 0a eb af 90 00 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00  VirtualAlloc
	condition:
		any of ($a_*)
 
}