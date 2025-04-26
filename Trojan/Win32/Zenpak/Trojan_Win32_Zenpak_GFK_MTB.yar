
rule Trojan_Win32_Zenpak_GFK_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 d0 89 c2 40 8d 05 ?? ?? ?? ?? 01 38 29 c2 83 f2 ?? 31 35 ?? ?? ?? ?? 83 f0 ?? 8d 05 ?? ?? ?? ?? 89 18 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}