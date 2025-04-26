
rule Trojan_Win32_RemcosRAT_B_MTB{
	meta:
		description = "Trojan:Win32/RemcosRAT.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 7d f8 05 ?? 00 00 0f 83 ?? 00 00 00 8b 4d f8 8a 94 0d ec ?? ff ff 88 55 ff 0f b6 45 ff } //2
		$a_01_1 = {88 45 ff 0f b6 4d ff } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}