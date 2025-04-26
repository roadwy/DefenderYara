
rule Trojan_Win32_Tnega_UJK_MTB{
	meta:
		description = "Trojan:Win32/Tnega.UJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c2 33 d2 03 c6 f7 f1 8d 0c 3e 46 8a 04 0b 8a 92 ?? ?? ?? ?? 32 c2 88 01 b9 1e 00 00 00 3b 75 f8 72 dc } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}