
rule Trojan_Win32_Dllhijack_GCN_MTB{
	meta:
		description = "Trojan:Win32/Dllhijack.GCN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 57 53 55 83 ec ?? 8b 3d ?? ?? ?? ?? 64 a1 18 00 00 00 8b 40 30 8b 58 0c 83 c3 0c 8b 13 3b d3 ?? ?? 33 ed 8b 72 ?? 8b cd 0f b7 06 85 c0 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}