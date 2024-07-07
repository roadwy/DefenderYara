
rule Ransom_Win32_NoEscape_MKV_MTB{
	meta:
		description = "Ransom:Win32/NoEscape.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 d1 03 c2 25 90 01 04 79 90 01 01 48 0d 90 01 04 40 89 85 c8 fe ff ff 0f b6 84 05 e8 fe ff ff 88 84 3d e8 fe ff ff 8b 85 c8 fe ff ff 88 8c 05 e8 fe ff ff 0f b6 84 3d e8 fe ff ff 8b 8d c4 fe ff ff 03 c2 0f b6 c0 0f b6 84 05 90 01 04 32 06 0f b6 c0 50 e8 90 01 04 46 3b b5 90 01 04 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}