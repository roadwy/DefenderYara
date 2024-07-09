
rule Trojan_Win32_Zenpak_GAF_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 18 89 d0 31 c2 31 2d ?? ?? ?? ?? 42 29 d0 29 d0 89 3d ?? ?? ?? ?? e9 ?? ?? ?? ?? 01 c2 01 d0 83 f2 ?? 31 35 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}