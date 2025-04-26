
rule Trojan_Win32_Zenpak_GZT_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GZT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 30 8d 05 ?? ?? ?? ?? ff d0 89 c2 8d 05 ?? ?? ?? ?? 89 18 42 01 3d ?? ?? ?? ?? 42 31 d0 89 e8 50 8f 05 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}