
rule Trojan_Win32_Ursnif_GNT_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c1 35 83 f1 1a 0f b7 95 ?? ?? ?? ?? 0f b7 85 ?? ?? ?? ?? 2b d0 0b ca 88 4d ?? 83 3d ?? ?? ?? ?? 64 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}