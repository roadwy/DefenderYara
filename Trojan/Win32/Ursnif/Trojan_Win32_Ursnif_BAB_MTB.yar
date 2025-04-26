
rule Trojan_Win32_Ursnif_BAB_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c0 2b c6 89 94 29 ?? ?? ?? ?? 8d 44 07 3f 8b 3d ?? ?? ?? ?? 83 c1 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}