
rule Trojan_Win32_AllegatoRAT_RD_MTB{
	meta:
		description = "Trojan:Win32/AllegatoRAT.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 8a 14 37 03 c2 99 f7 f9 8a 04 17 88 45 f2 8d 45 e0 8b 55 fc 8b 4d f4 8a 54 0a ff 8a 4d f2 32 d1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}