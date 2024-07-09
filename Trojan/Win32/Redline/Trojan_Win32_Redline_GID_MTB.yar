
rule Trojan_Win32_Redline_GID_MTB{
	meta:
		description = "Trojan:Win32/Redline.GID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 4c 3d ?? 88 4c 35 ?? 88 5c 3d ?? 0f b6 54 35 ?? 0f b6 cb 03 d1 0f b6 ca 0f b6 4c 0d 10 32 88 ?? ?? ?? ?? 88 88 ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? 40 eb } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}