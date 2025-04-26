
rule Trojan_Win32_Emotet_DDC_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 f7 fb 8b 6c 24 ?? 33 c0 68 ?? ?? ?? ?? 8a 04 2a 03 c1 b9 ?? ?? ?? ?? 89 54 24 ?? 8d 1c 2a 99 f7 f9 33 c0 8a 03 8b ca 89 4c 24 ?? 03 cd 8b e9 8a 55 00 88 13 88 45 00 33 c0 33 d2 8a 03 8a 11 03 c2 b9 ?? ?? ?? ?? 99 f7 f9 8b 44 24 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}