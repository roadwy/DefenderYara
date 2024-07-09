
rule Trojan_Win32_Redline_RE_MTB{
	meta:
		description = "Trojan:Win32/Redline.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 02 0f b6 00 0f b6 c0 88 45 ?? c7 45 ?? 02 00 00 00 0f b6 45 ?? 8d 50 ?? 8b 45 ?? 83 ?? ?? 31 d0 88 85 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 83 c0 03 0f b6 00 0f b6 c0 88 45 ?? c7 45 ?? 03 00 00 00 0f b6 45 ?? 8d 50 ?? 8b 45 ?? 83 ?? ?? 31 d0 88 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}