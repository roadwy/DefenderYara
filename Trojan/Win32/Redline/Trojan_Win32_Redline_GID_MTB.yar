
rule Trojan_Win32_Redline_GID_MTB{
	meta:
		description = "Trojan:Win32/Redline.GID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f b6 4c 3d 90 01 01 88 4c 35 90 01 01 88 5c 3d 90 01 01 0f b6 54 35 90 01 01 0f b6 cb 03 d1 0f b6 ca 0f b6 4c 0d 10 32 88 90 01 04 88 88 90 01 04 c7 45 90 01 05 40 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}