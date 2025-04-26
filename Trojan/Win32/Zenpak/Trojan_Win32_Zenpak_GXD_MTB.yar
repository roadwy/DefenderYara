
rule Trojan_Win32_Zenpak_GXD_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GXD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 c8 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 c0 5d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}