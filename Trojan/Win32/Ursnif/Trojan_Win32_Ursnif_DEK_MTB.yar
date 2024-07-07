
rule Trojan_Win32_Ursnif_DEK_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.DEK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d0 d3 e2 8b c8 c1 e9 05 03 8d 90 01 01 fe ff ff 03 95 90 01 01 fe ff ff 89 3d 90 01 04 33 d1 8b 4d f8 03 c8 33 d1 29 55 f4 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}