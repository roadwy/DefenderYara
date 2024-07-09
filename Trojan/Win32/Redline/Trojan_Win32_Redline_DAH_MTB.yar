
rule Trojan_Win32_Redline_DAH_MTB{
	meta:
		description = "Trojan:Win32/Redline.DAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 84 3d ?? ?? ff ff 88 84 0d ?? ?? ff ff 8a 85 ?? ?? ff ff 88 84 3d ?? ?? ff ff 0f b6 84 0d ?? ?? ff ff 03 85 ?? ?? ff ff 0f b6 c0 0f b6 84 05 ?? ?? ff ff 30 86 [0-04] 46 81 fe [0-04] 0f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}