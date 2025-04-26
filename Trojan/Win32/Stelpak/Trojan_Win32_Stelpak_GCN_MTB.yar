
rule Trojan_Win32_Stelpak_GCN_MTB{
	meta:
		description = "Trojan:Win32/Stelpak.GCN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 84 1c ?? ?? ?? ?? 8b 4c 24 ?? 03 c2 0f b6 c0 89 74 24 ?? 0f b6 84 04 ?? ?? ?? ?? 30 04 39 47 3b 7c 24 ?? 0f 8c } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}