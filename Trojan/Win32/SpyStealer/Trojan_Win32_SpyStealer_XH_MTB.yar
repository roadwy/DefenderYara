
rule Trojan_Win32_SpyStealer_XH_MTB{
	meta:
		description = "Trojan:Win32/SpyStealer.XH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 1d a1 ed eb 01 d3 33 c0 79 ?? ?? 4d 82 71 ?? ?? 04 ?? 33 28 a2 ?? ?? ?? ?? ea } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}