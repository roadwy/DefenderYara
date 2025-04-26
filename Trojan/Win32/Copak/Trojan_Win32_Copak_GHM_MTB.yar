
rule Trojan_Win32_Copak_GHM_MTB{
	meta:
		description = "Trojan:Win32/Copak.GHM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 14 24 8b 14 24 83 c4 04 e8 ?? ?? ?? ?? 01 f2 81 c2 ?? ?? ?? ?? 31 19 81 c1 ?? ?? ?? ?? 39 c1 75 ?? 81 ea } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}