
rule Trojan_Win32_Zenpak_GMA_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c2 89 e0 50 8f 05 ?? ?? ?? ?? 89 d0 42 e8 ?? ?? ?? ?? c3 8d 05 ?? ?? ?? ?? 01 30 31 3d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}