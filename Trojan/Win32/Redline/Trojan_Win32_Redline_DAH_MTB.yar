
rule Trojan_Win32_Redline_DAH_MTB{
	meta:
		description = "Trojan:Win32/Redline.DAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {0f b6 84 3d 90 01 02 ff ff 88 84 0d 90 01 02 ff ff 8a 85 90 01 02 ff ff 88 84 3d 90 01 02 ff ff 0f b6 84 0d 90 01 02 ff ff 03 85 90 01 02 ff ff 0f b6 c0 0f b6 84 05 90 01 02 ff ff 30 86 90 02 04 46 81 fe 90 02 04 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}