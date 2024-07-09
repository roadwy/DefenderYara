
rule Trojan_Win32_Ursnif_DF_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 c6 99 8b c8 89 3d ?? ?? ?? ?? 0f a4 ca 01 8b 54 24 34 8d 46 fd 03 c9 83 c1 bb 8d 04 41 0f b7 c0 89 44 24 40 8b 02 05 a8 f8 02 01 89 02 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}