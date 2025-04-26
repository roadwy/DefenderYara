
rule Trojan_Win32_Redline_GC_MTB{
	meta:
		description = "Trojan:Win32/Redline.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 15 04 60 56 00 a1 00 c0 56 00 03 85 ?? ?? ?? ?? 0f b6 08 33 ca 8b 15 ?? ?? ?? ?? 03 95 ?? ?? ?? ?? 88 0a eb bc } //10
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}